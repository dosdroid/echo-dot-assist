/*
 * AirPlay receiver: the Echo as an AirPlay speaker for iPhones, iPads and Macs.  Optional (setting `airplay`, off by
 * default), experimental.
 *
 * The protocol is not ours: Shairport Sync (github.com/mikebrady/shairport-sync, the receiver Music Assistant's
 * AirPlay Receiver runs too; tools/airplay/build.sh builds the version its image pins) runs beside hassmic as a
 * program of its own, in classic AirPlay ("AirPlay 1": ALAC over RTP, 44.1 kHz stereo).  AirPlay 2 would need PTP on
 * UDP 319/320 as root, outside what the firewall admits.  It is a static musl binary next to hassmic: built on
 * pthread_cancel, it cannot be linked against bionic, let alone into hassmic.
 *
 *   audio      its stdout backend into a pipe: PCM as it is due, at the sender's pace.  Played on the music stream
 *              (Sendspin's: one of the two at a time, core_music_claim) with QUEUE_US of it between Shairport Sync
 *              and the speaker, so a pause, a skip or a wake word's duck is heard at once; the sender's clock against
 *              the output's is followed by the rate (resample.h's servo), not by frames dropped or repeated.  Each
 *              frame is heard when the sender wants it (audio_thread says how): video stays in step.
 *   events     its metadata pipe (a FIFO in state/airplay): play begin/end, flush, the sender's volume, the track and
 *              its artwork (the Echo Show's screen), and the sender's address and DACP ids.
 *   control    back to the sender by DACP (HTTP on the port its _dacp._tcp record names, asked of the sender itself by
 *              unicast mDNS): pause, play, next, previous, volume.  A stop is never left to it: the Echo goes silent
 *              at once (the audio dropped here), and a sender that does not take the pause loses its session.
 *   mDNS       Shairport Sync's "external" backend runs `avahi-publish-service <name> _raop._tcp <port> <txt>...`;
 *              on its PATH that is a link to hassmic (airplay_publish), which writes those very records into the stock
 *              avahi's service folder as hassmic-airplay.service and removes it when told to go.  No second responder.
 *
 * Ports: RTSP on TCP 28933, RTP/control/timing on UDP 28934..28943, inside the firewall's 16384-32767.  No password:
 * as with any AirPlay 1 speaker, anyone on the network can play (docs/SECURITY.md).
 *
 * Never hassmic's direct child (clock.c: Amazon's DHA module waits for all children): double-forked, its pid in
 * state/airplay/pid so one left behind by a hassmic that died is ended before the next starts (it holds the port).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "airplay.h"
#include "audio.h"
#include "core.h"
#include "duck.h"
#include "hash.h"
#include "net.h"
#include "resample.h"
#include "screen.h"
#include "settings.h"
#include "statefile.h"

#define RATE 44100
#define FRAME 4                         /* stereo s16 */
#define PORT 28933                      /* RTSP; UDP from PORT + 1, UDP_RANGE of them (three in use per session) */
#define UDP_RANGE 10
#define QUEUE_US 120000                 /* kept in the output, as Sendspin's: reacts fast to pause / duck / volume */
#define IDLE_CLOSE_MS 400               /* no audio for this long: the output goes (Sendspin may have it) */
#define IDLE_OFF_MS 1500                /* ...and this long: nothing plays, as far as the core is concerned */
#define HUSH_GIVE_UP_MS 3000            /* a sender still sending this long after its pause was asked for: session dropped */
#define RESUME_MS (30 * 60 * 1000)      /* how long the button resumes what the Echo paused */

static atomic_int enabled, started;
static atomic_int drop;                 /* events -> audio thread: forget what is queued, now (flush, pause, end) */
static atomic_int hushed;               /* the Echo paused it: audio is discarded until the sender starts anew */
static atomic_int playing;              /* audio flows and is heard */
static atomic_int restart;              /* the receiver is to be started anew (session dropped, setting changed) */
static atomic_llong hushed_at, paused_at;   /* ms; paused_at 0: nothing of ours to resume */
static atomic_int sender_pct = -1;      /* the volume the sender last set: not told back to it */

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;        /* the session's facts and the command queue */
static pthread_cond_t wake = PTHREAD_COND_INITIALIZER;
static char client_ip[64], active_remote[32], dacp_id[40];      /* (lock) from the events; empty: none */
static char dacp_for[40]; static int dacp_port;                 /* (lock) the port found for that DACP id */
#define CMDS 8
static struct cmd { char path[80]; int must; } cmds[CMDS];      /* (lock) must: failing it drops the session */
static int ncmds;

static long long now_ms(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}

static const char *state_dir(void) { const char *e = getenv("HASSMIC_STATE"); return e ? e : "/data/local/hassmic/state"; }
static void in_state(char *out, size_t n, const char *f) { snprintf(out, n, "%s/airplay%s%s", state_dir(), *f ? "/" : "", f); }

static const char *binary(void)
{
    static char p[PATH_MAX]; const char *e = getenv("HASSMIC_SHAIRPORT");
    if (e) return e;
    if (!p[0]) {
        ssize_t k = readlink("/proc/self/exe", p, sizeof p - 32);
        if (k <= 0) snprintf(p, sizeof p, "/system/hassmic/shairport-sync");
        else { p[k] = 0; char *s = strrchr(p, '/'); snprintf(s ? s + 1 : p, 32, "shairport-sync"); }
    }
    return p;
}

int airplay_available(void) { return access(binary(), X_OK) == 0; }

/* ---------------------------------------------------------------- mDNS: what Shairport Sync wants announced */

/* The service file's path: beside hassmic's own in avahi's folder (root made it the daemon user's, main.sh) */
static void service_file(char *out, size_t n)
{
    const char *e = getenv("HASSMIC_AIRPLAY_MDNS"), *m = getenv("HASSMIC_MDNS_FILE");
    if (e) { snprintf(out, n, "%s", e); return; }
    snprintf(out, n, "%s", m ? m : "/data/misc/avahi/services/hassmic.service");
    char *s = strrchr(out, '/');
    snprintf(s ? s + 1 : out, n - (size_t)(s ? s + 1 - out : 0), "hassmic-airplay.service");
}

static void xml(FILE *f, const char *s)
{
    for (; *s; s++) {
        if (*s == '&') fputs("&amp;", f); else if (*s == '<') fputs("&lt;", f); else if (*s == '>') fputs("&gt;", f);
        else if ((unsigned char)*s >= 0x20) fputc(*s, f);
    }
}

int airplay_publish(int argc, char **argv)
{
    char path[PATH_MAX]; struct statefile s; sigset_t set; int sig;
    if (argc < 4) return 2;
    service_file(path, sizeof path);
    /* gone with Shairport Sync however it ends (it sends SIGTERM when it stops announcing; killed, the kernel does) */
    sigemptyset(&set); sigaddset(&set, SIGTERM); sigaddset(&set, SIGINT); sigaddset(&set, SIGHUP);
    sigprocmask(SIG_BLOCK, &set, NULL);
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() == 1) return 0;
    if (statefile_open(&s, path, 0644)) { fprintf(stderr, "airplay: cannot write %s (%s)\n", path, strerror(errno)); return 1; }
    fchmod(fileno(s.f), 0644);                      /* avahi reads it: past hassmic's umask */
    fputs("<?xml version=\"1.0\" standalone='no'?>\n<!DOCTYPE service-group SYSTEM \"avahi-service.dtd\">\n<service-group>\n  <name>", s.f);
    xml(s.f, argv[1]);
    fputs("</name>\n  <service><type>", s.f); xml(s.f, argv[2]);
    fprintf(s.f, "</type><port>%d</port>\n", atoi(argv[3]));
    for (int i = 4; i < argc; i++) { fputs("    <txt-record>", s.f); xml(s.f, argv[i]); fputs("</txt-record>\n", s.f); }
    fputs("  </service>\n</service-group>\n", s.f);
    if (statefile_commit(&s)) { fprintf(stderr, "airplay: cannot write %s (%s)\n", path, strerror(errno)); return 1; }
    sigwait(&set, &sig);
    unlink(path);
    return 0;
}

/* ---------------------------------------------------------------- the receiver process */

static pid_t child = -1;                /* audio thread only */
static int child_out = -1;

static void pid_path(char *p, size_t n) { in_state(p, n, "pid"); }

/* One a hassmic that died left behind: it still has the port.  Only if that pid is a shairport-sync now */
static void kill_stale(void)
{
    char p[PATH_MAX], b[64], cl[PATH_MAX + 32]; pid_path(p, sizeof p);
    FILE *f = fopen(p, "r"); int pid = 0;
    if (f) { if (fgets(b, sizeof b, f)) pid = atoi(b); fclose(f); }
    unlink(p);
    if (pid <= 1) return;
    snprintf(cl, sizeof cl, "/proc/%d/cmdline", pid);
    f = fopen(cl, "r"); if (!f) return;
    size_t k = fread(cl, 1, sizeof cl - 1, f); fclose(f); cl[k] = 0;
    if (!strstr(cl, "shairport-sync")) return;
    fprintf(stderr, "airplay: an earlier receiver (pid %d) is still there, ended\n", pid);
    kill(-pid, SIGKILL); kill(pid, SIGKILL);
    usleep(200000);
}

static void write_config(char *conf, size_t n)
{
    char meta[PATH_MAX], bin[PATH_MAX], link[PATH_MAX], me[PATH_MAX]; struct statefile s;
    in_state(conf, n, ""); mkdir(conf, 0700);
    in_state(bin, sizeof bin, "bin"); mkdir(bin, 0700);
    in_state(link, sizeof link, "bin/avahi-publish-service");
    ssize_t k = readlink("/proc/self/exe", me, sizeof me - 1);
    if (k > 0) { me[k] = 0; unlink(link); if (symlink(me, link)) fprintf(stderr, "airplay: cannot link %s (%s)\n", link, strerror(errno)); }
    in_state(meta, sizeof meta, "meta");
    in_state(conf, n, "shairport-sync.conf");
    if (statefile_open(&s, conf, 0600)) return;
    pthread_mutex_lock(&core_lock); int vol = core_volume(); pthread_mutex_unlock(&core_lock);
    /* ignore_volume_control: full-scale PCM, the sender's slider becomes the Echo's volume (events).  The latency
     * default_airplay_volume: what it reports until
     * the sender has set one (iOS does at once), so that is the Echo's volume as it is, not Shairport Sync's -24 dB.
     * audio_backend_buffer_desired_length: how early each frame comes down the pipe, and so how much stands between
     * the sender and the speaker (audio_thread): its default for stdout is a whole second, which a pause would still
     * have had to drop, and which kept the pipe and the output full (the PC: the rate at its +0.5 % stop, 660 Hz
     * played at 664).  The latency offset: what the output adds that its queue does not show (Android's burst). */
    fprintf(s.f, "general = {\n  name = \"%s\";\n  port = %d;\n  udp_port_base = %d;\n  udp_port_range = %d;\n"
                 "  ignore_volume_control = \"yes\";\n  default_airplay_volume = %.1f;\n  output_backend = \"stdout\";\n  mdns_backend = \"external-avahi\";\n"
                 "  audio_backend_latency_offset_in_seconds = %.3f;\n  audio_backend_buffer_desired_length_in_seconds = %.3f;\n};\n"
                 "metadata = {\n  enabled = \"yes\";\n  include_cover_art = \"yes\";\n  pipe_name = \"%s\";\n  pipe_timeout = 5000;\n};\n"
                 "sessioncontrol = {\n  allow_session_interruption = \"yes\";\n  session_timeout = 20;\n};\n",
            core_name, PORT, PORT + 1, UDP_RANGE, vol <= 0 ? -30.0 : -30.0 + vol * 0.3, -(double)music_prime_us() / 1e6, QUEUE_US / 1e6, meta);
    statefile_commit(&s);
}

static int child_start(void)
{
    char conf[PATH_MAX], path[PATH_MAX + 64], svc[PATH_MAX + 32], sf[PATH_MAX], bin[PATH_MAX], pp[PATH_MAX];
    int pout[2], ppid[2]; const char *prog = binary();
    kill_stale();
    write_config(conf, sizeof conf);
    service_file(sf, sizeof sf); unlink(sf);
    in_state(bin, sizeof bin, "bin");
    const char *old = getenv("PATH");
    snprintf(path, sizeof path, "PATH=%s:%s", bin, old ? old : "/system/bin");
    snprintf(svc, sizeof svc, "HASSMIC_AIRPLAY_MDNS=%s", sf);
    /* everything the child needs made before the fork; after it only async-signal-safe calls (screen.c ui_start) */
    extern char **environ;
    size_t ne = 0; while (environ[ne]) ne++;
    char **envp = malloc((ne + 3) * sizeof *envp);
    if (!envp) return -1;
    size_t m = 0; envp[m++] = path; envp[m++] = svc;
    for (size_t i = 0; i < ne; i++) if (strncmp(environ[i], "PATH=", 5) && strncmp(environ[i], "HASSMIC_AIRPLAY_MDNS=", 21)) envp[m++] = environ[i];
    envp[m] = NULL;
    char *argv_[] = { "shairport-sync", "-c", conf, NULL };       /* its warnings: stderr, the log */
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536) maxfd = 65536;
    gid_t eg = getegid();
    if (pipe2(pout, O_CLOEXEC)) { free(envp); return -1; }
    if (pipe2(ppid, O_CLOEXEC)) { close(pout[0]); close(pout[1]); free(envp); return -1; }
    pid_t mid = fork();
    if (mid == 0) {
        pid_t g = fork();
        if (g > 0) { ssize_t w = write(ppid[1], &g, sizeof g); (void)w; _exit(0); }
        if (g < 0) _exit(1);
        setpgid(0, 0);                                  /* a group of its own: the publisher goes with it */
        int o = fcntl(pout[1], F_DUPFD, 3);
        if (o < 0 || dup2(o, 1) < 0) _exit(127);
        for (long d = 3; d < maxfd; d++) close((int)d);     /* none of hassmic's sockets in it; stderr: the log */
        if (setregid(eg, eg)) _exit(127);               /* as main.c's child_ids: no AT_SECURE, plain group */
        execve(prog, argv_, envp);
        _exit(127);
    }
    free(envp);
    close(pout[1]); close(ppid[1]);
    pid_t g = -1;
    if (mid < 0 || read(ppid[0], &g, sizeof g) != (ssize_t)sizeof g) g = -1;
    close(ppid[0]);
    if (g <= 0) { close(pout[0]); fprintf(stderr, "airplay: the receiver cannot be started (%s)\n", strerror(errno)); return -1; }
    child = g; child_out = pout[0];
    fcntl(child_out, F_SETFL, fcntl(child_out, F_GETFL) | O_NONBLOCK);
    pid_path(pp, sizeof pp);
    char b[24]; int l = snprintf(b, sizeof b, "%d\n", (int)g);
    statefile_write(pp, 0600, b, (size_t)l);
    fprintf(stderr, "airplay: receiver started as \"%s\" (pid %d, port %d)\n", core_name, (int)g, PORT);
    return 0;
}

static void child_stop(void)
{
    char p[PATH_MAX];
    if (child > 0) {
        kill(-child, SIGTERM); kill(child, SIGTERM);
        /* not ours to wait for (init's): until its end of the pipe closes, 1 s at most, then the hard way */
        struct pollfd pfd = { .fd = child_out, .events = POLLIN }; char buf[4096]; long long t0 = now_ms();
        while (now_ms() - t0 < 1000) {
            if (poll(&pfd, 1, 50) > 0 && read(child_out, buf, sizeof buf) == 0) break;
        }
        kill(-child, SIGKILL); kill(child, SIGKILL);
    }
    if (child_out >= 0) close(child_out);
    child = -1; child_out = -1;
    pid_path(p, sizeof p); unlink(p);
    service_file(p, sizeof p); unlink(p);               /* (the publisher's own job; killed, it could not) */
}

/* ---------------------------------------------------------------- audio */

static int out_open_;                   /* audio thread only */

static void out_close(void)
{
    if (!out_open_) return;
    music_close(); core_music_release(MUSIC_AIRPLAY); out_open_ = 0;
}

static void silence(long long us)
{
    static const int16_t zero[RATE / 50 * 2];
    for (long long f = us * RATE / 1000000; f > 0; ) { size_t k = f > RATE / 50 ? RATE / 50 : (size_t)f; music_write(zero, k * FRAME); f -= (long long)k; }
}

static void set_playing(int on)
{
    if (atomic_exchange(&playing, on) == on) return;
    core_music(MUSIC_AIRPLAY, on);
    fprintf(stderr, "airplay: %s\n", on ? "playing" : "stopped");
}

static void session_forget(void)
{
    pthread_mutex_lock(&lock);
    client_ip[0] = active_remote[0] = dacp_id[0] = 0; ncmds = 0;
    pthread_mutex_unlock(&lock);
    atomic_store(&paused_at, 0); atomic_store(&sender_pct, -1);
}

/* What Shairport Sync's stdout backend writes is a clock in samples: when a stream starts (and after every flush) the
 * silence from now until the first frame is due, all at once, then each frame `audio_backend_buffer_desired_length`
 * before it is due.  Whoever reads it is to play all of it at the speed it was made at; then every frame is heard when
 * the sender wants it.  So here: nothing dropped and nothing added, read only as fast as the output plays (the rest
 * waits in the pipe, 64 KB = 0.37 s, and Shairport Sync behind it), and
 *   - the time between the stream's first bytes and the output being open (music_open, Sendspin letting go of it) is
 *     taken out of that lead-in silence (`skip`): what real time passed is not played late;
 *   - desired length = QUEUE_US, so in step means QUEUE_US of it between Shairport Sync and the speaker: the servo
 *     holds the output's queue plus what waits in the pipe at that (the sender's clock against the output's), left
 *     alone while more waits (the lead-in, a backlog after the output ran dry: that is no drift);
 *   - a flush (pause, skip, seek) ends a stream: what the output holds is dropped at once, and of what follows, the
 *     old stream's last frames (up to QUEUE_US were on their way).  Its event and the next stream's lead-in come by
 *     two pipes, in either order, and a lead-in cut short would have the new stream early for good (seen: a skip's
 *     lead-in lost 80 ms, the next track played 0.5 % slow for a quarter of a minute to make up).  So the boundary
 *     is read off the audio: the lead-in is digital silence.  If silence was already being read when the event is
 *     seen, the new stream began where that silence did; else what comes until silence does is the old one's;
 *   - not every stream has a lead-in: after a flush with the next packets right behind it (a skip) Shairport Sync
 *     writes nothing for two seconds and then each frame as it falls due less the desired length, the pipe and the
 *     output empty before it (measured on its stdout alone, 2026-11-11).  Left to the servo that was the next track
 *     0.5 % slow for 24 s to gather a queue (880 Hz at 876), any jitter a dropout meanwhile.  So a stream that opens
 *     with nothing ahead of it gets its queue as silence first, as one that ran dry does;
 *   - an output that ran dry mid-stream (packets came late) has shifted everything by the gap: the excess is dropped
 *     at once, a second cut right behind the first rather than twenty seconds of music 0.5 % fast.
 * Shairport Sync calls this backend unsynchronised, and by its own schedule it is good to some 70 ms: with a lead-in
 * the first frame is due 2.32 s after the sender's first packet, without one 2.25 s (same measurement). */
#define BLOCK (RATE / 50)               /* frames read at a time, 20 ms: a flush or a pause is seen between two */
#define GATE_US (QUEUE_US + 20000)      /* more than this queued: the output has enough, the pipe keeps the rest */
#define BACKLOG_US 100000               /* this much over QUEUE_US: lead-in or backlog, the servo waits */

static long long us_now(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000LL + t.tv_nsec / 1000;
}

static void *audio_thread(void *arg)
{
    (void)arg;
    static char buf[BLOCK * FRAME + FRAME]; static int16_t out[RS_OUT_MAX(BLOCK) * 2];
    size_t have = 0; long long last_audio = 0, retry_at = 0, stream_t0 = 0, consumed = 0, skip = 0, stat_t = 0; int backoff = 1000, wrote = 0, dry = 0, fresh = 0;
    long long quiet_t0 = 0, quiet = 0, purge = 0, purge_until = 0;     /* the silence being read: since when, how many frames; old frames to drop */
    struct resampler rs; struct rate_servo servo = { 0 }; double step = 1, rate_sum = 0; long rate_n = 0; float duck_g = 1;
    rs_reset(&rs);
    for (;;) {
        if (!atomic_load(&enabled)) {
            if (child > 0) { out_close(); set_playing(0); child_stop(); session_forget(); fprintf(stderr, "airplay: off\n"); }
            atomic_store(&hushed, 0); atomic_store(&restart, 0);
            usleep(200000);
            continue;
        }
        if (atomic_exchange(&restart, 0) && child > 0) { out_close(); set_playing(0); child_stop(); session_forget(); atomic_store(&hushed, 0); retry_at = 0; }
        if (child <= 0) {
            if (now_ms() < retry_at) { usleep(100000); continue; }
            if (!airplay_available() || child_start()) { retry_at = now_ms() + 30000; continue; }
            have = 0; stream_t0 = 0; quiet = 0; purge = 0;
        }
        if (atomic_exchange(&drop, 0)) {
            out_close();
            if (quiet) { stream_t0 = quiet_t0; consumed = quiet; purge = 0; }      /* the new stream's lead-in, begun */
            else { stream_t0 = 0; purge = (long long)RATE * (QUEUE_US + 30000) / 1000000; purge_until = now_ms() + 500; }
        }
        long long now = now_ms();
        if (out_open_ && music_queued_us() > GATE_US) { last_audio = now; usleep(4000); continue; }
        struct pollfd pfd = { .fd = child_out, .events = POLLIN };
        if (poll(&pfd, 1, 20) <= 0) {
            if (out_open_ && now - last_audio > IDLE_CLOSE_MS) out_close();
            if (now - last_audio > IDLE_CLOSE_MS) { stream_t0 = 0; quiet = 0; }       /* what comes next is a stream of its own */
            if (now - last_audio > IDLE_OFF_MS) set_playing(0);
            continue;
        }
        ssize_t r = read(child_out, buf + have, BLOCK * FRAME - have);
        if (r < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (r <= 0) {
            /* it ended (a crash: its ALAC decoder does not survive every malformed packet): anew, not in a tight loop */
            out_close(); set_playing(0); child_stop(); session_forget(); atomic_store(&hushed, 0);
            fprintf(stderr, "airplay: the receiver ended, started again in %d s\n", backoff / 1000);
            retry_at = now + backoff; backoff = backoff < 60000 ? backoff * 2 : 60000;
            continue;
        }
        have += (size_t)r;
        size_t frames = have / FRAME;
        if (!frames) continue;
#define EAT(k) do { size_t n_ = (k), k_ = n_ * FRAME; memmove(buf, buf + k_, have - k_); have -= k_; frames -= n_; consumed += (long long)n_; } while (0)   /* whole frames gone, a cut one stays */
        if (now - last_audio > 10000) backoff = 1000;       /* it works: the next crash is a first one again */
        last_audio = now;
        /* silent from which frame on (32 frames of it at least: not a waveform through zero), and since when */
        const int16_t *pcm = (const int16_t *)buf; size_t zfrom = frames;
        while (zfrom > 0 && !pcm[2 * zfrom - 2] && !pcm[2 * zfrom - 1]) zfrom--;
        if (purge) {                                        /* after a flush: the old stream's frames, until silence */
            size_t gone = now > purge_until ? 0 : frames - zfrom >= 32 || quiet ? zfrom : frames;
            if ((long long)gone > purge) gone = (size_t)purge;
            purge = gone == frames ? purge - (long long)gone : 0;
            if (gone) { EAT(gone); zfrom -= gone; quiet = 0; if (!frames) continue; }
        }
        if (zfrom == 0) { if (!quiet) quiet_t0 = us_now(); quiet += (long long)frames; }
        else if (frames - zfrom >= 32) { quiet_t0 = us_now(); quiet = (long long)(frames - zfrom); }
        else quiet = 0;
        if (!stream_t0) { stream_t0 = us_now(); consumed = 0; skip = 0; }
        if (atomic_load(&hushed)) {
            /* paused from here: nothing of it is heard.  A sender that goes on regardless is no use to hold on to */
            EAT(frames); out_close(); set_playing(0);
            if (now - atomic_load(&hushed_at) > HUSH_GIVE_UP_MS) {
                fprintf(stderr, "airplay: the sender did not pause, session dropped\n");
                atomic_store(&restart, 1);
            }
            continue;
        }
        if (!out_open_) {
            /* Sendspin's stream on the same output closes within its next chunk once core_music paused it */
            if (!core_music_claim(MUSIC_AIRPLAY)) { set_playing(1); EAT(frames); continue; }
            if (music_open(RATE, 2)) { core_music_release(MUSIC_AIRPLAY); EAT(frames); continue; }
            out_open_ = 1; duck_g = 1; wrote = dry = 0; fresh = 1;
            silence(music_prime_us());                      /* (Shairport Sync was told of it: the latency offset) */
            rs_reset(&rs); step = rate_servo_snap(&servo);
            skip = (us_now() - stream_t0) * RATE / 1000000 - consumed;
        }
        set_playing(1);
        if (skip > 0) { size_t k = (long long)frames < skip ? frames : (size_t)skip; skip -= (long long)k; EAT(k); if (!frames) continue; }
        int waiting = 0; ioctl(child_out, FIONREAD, &waiting);
        long long q = music_queued_us(), held = q + (long long)waiting / FRAME * 1000000 / RATE;
        if (wrote && q <= 0) dry = 1;
        if ((fresh || dry) && held < QUEUE_US - 30000) {    /* nothing ahead of it: the queue made of a gap, at once */
            silence(QUEUE_US - held); held = QUEUE_US;
            rs_reset(&rs); step = rate_servo_snap(&servo);
        } else if (dry && held > QUEUE_US + 20000) {       /* behind by what the gap was: caught up in one cut */
            skip = (held - QUEUE_US) * RATE / 1000000; dry = 0;
            rs_reset(&rs); step = rate_servo_snap(&servo);
            continue;
        }
        fresh = 0;
        if (held > QUEUE_US + BACKLOG_US) step = rate_servo_snap(&servo);
        else { step = rate_servo(&servo, (double)(QUEUE_US - held), (double)frames / RATE); dry = 0; }
        size_t n = rs_run(&rs, (const int16_t *)buf, frames, step, out);
        music_duck(out, n, RATE, &duck_g, duck_active() ? settings_duck_gain() : 1);    /* under the voice assistant */
        music_write(out, n * FRAME); wrote = 1;
        rate_sum += step - 1; rate_n++;
        if (now - stat_t > 60000) {                         /* a line a minute while it plays: how the clocks get on */
            if (stat_t) fprintf(stderr, "airplay: %lld ms held, rate %+.0f ppm (the clocks' difference: %+.0f ppm)\n", held / 1000, rate_sum / rate_n * 1e6, servo.drift * 1e6);
            stat_t = now; rate_sum = 0; rate_n = 0;
        }
        EAT(frames);
    }
    return NULL;
}

/* ---------------------------------------------------------------- DACP: commands to the sender */

static void command(const char *path, int must)
{
    pthread_mutex_lock(&lock);
    if (!strncmp(path, "setproperty", 11))              /* a volume not sent yet is replaced, not followed */
        for (int i = 0; i < ncmds; i++) if (!strncmp(cmds[i].path, "setproperty", 11)) { memmove(cmds + i, cmds + i + 1, (size_t)(ncmds - i - 1) * sizeof *cmds); ncmds--; break; }
    if (ncmds < CMDS) { snprintf(cmds[ncmds].path, sizeof cmds[ncmds].path, "%s", path); cmds[ncmds++].must = must; }
    pthread_cond_signal(&wake);
    pthread_mutex_unlock(&lock);
}

static int dacp_send(const char *ip, int port, const char *remote, const char *path)
{
    char ps[8], req[300], resp[64]; snprintf(ps, sizeof ps, "%d", port);
    int s = net_connect(ip, ps, 2);
    if (s < 0) return -1;
    int l = snprintf(req, sizeof req, "GET /ctrl-int/1/%s HTTP/1.1\r\nHost: %s:%d\r\nActive-Remote: %s\r\nConnection: close\r\n\r\n", path, ip, port, remote);
    ssize_t k = write(s, req, (size_t)l) == l ? read(s, resp, sizeof resp - 1) : -1;
    close(s);
    if (k < 12) return -1;
    resp[k] = 0;
    return !strncmp(resp, "HTTP/1.", 7) && resp[9] == '2' ? 0 : -1;
}

static void *dacp_thread(void *arg)
{
    (void)arg;
    for (;;) {
        struct cmd c; char ip[64], remote[32], id[40]; int port;
        pthread_mutex_lock(&lock);
        while (!ncmds) pthread_cond_wait(&wake, &lock);
        c = cmds[0]; memmove(cmds, cmds + 1, (size_t)(--ncmds) * sizeof *cmds);
        snprintf(ip, sizeof ip, "%s", client_ip); snprintf(remote, sizeof remote, "%s", active_remote); snprintf(id, sizeof id, "%s", dacp_id);
        port = !strcmp(dacp_for, id) ? dacp_port : 0;
        pthread_mutex_unlock(&lock);
        int ok = 0;
        if (ip[0] && remote[0] && id[0]) {
            if (!port) {
                /* the sender's own answer to where its remote control listens (iOS: a port per session) */
                char name[96]; struct in_addr a = { 0 };
                snprintf(name, sizeof name, "iTunes_Ctrl_%s._dacp._tcp.local", id);
                inet_pton(AF_INET, ip, &a);
                port = mdns_srv_port(name, a.s_addr);
                pthread_mutex_lock(&lock); snprintf(dacp_for, sizeof dacp_for, "%s", id); dacp_port = port; pthread_mutex_unlock(&lock);
                if (!port) fprintf(stderr, "airplay: the sender names no remote control port\n");
            }
            ok = port && !dacp_send(ip, port, remote, c.path);
            if (port && !ok) { pthread_mutex_lock(&lock); dacp_for[0] = 0; pthread_mutex_unlock(&lock); }     /* asked again next time */
        }
        if (ok) fprintf(stderr, "airplay: sender told \"%s\"\n", c.path);
        else if (c.must) { fprintf(stderr, "airplay: the sender could not be told \"%s\", session dropped\n", c.path); atomic_store(&restart, 1); }
    }
    return NULL;
}

static void hush(void)
{
    atomic_store(&hushed_at, now_ms()); atomic_store(&hushed, 1); atomic_store(&drop, 1);
    command("pause", 1);
}

/* `playing` goes down in the audio thread, with the next audio or the lack of it: until then a second ask is not one */
static int heard(void) { return atomic_load(&playing) && !atomic_load(&hushed); }

void airplay_pause(void) { if (heard()) { hush(); atomic_store(&paused_at, 0); } }

int airplay_stop(void)
{
    if (!heard()) return 0;
    hush(); atomic_store(&paused_at, now_ms());
    return 1;
}

int airplay_button(int resume)
{
    if (!resume) return airplay_stop();
    long long at = atomic_load(&paused_at);
    if (!at || now_ms() - at > RESUME_MS || !atomic_load(&hushed)) return 0;
    atomic_store(&paused_at, 0); atomic_store(&hushed, 0);
    command("play", 0);
    return 1;
}

int airplay_skip(int dir)
{
    if (!heard()) return 0;
    command(dir > 0 ? "nextitem" : "previtem", 0);
    return 1;
}

void airplay_volume_changed(int percent)
{
    char p[64];
    if (!heard() || percent == atomic_load(&sender_pct)) return;
    atomic_store(&sender_pct, percent);
    /* AirPlay's scale: -30 dB..0, -144 = muted */
    snprintf(p, sizeof p, "setproperty?dmcp.device-volume=%.2f", percent <= 0 ? -144.0 : -30.0 + percent * 0.3);
    command(p, 0);
}

/* ---------------------------------------------------------------- events (Shairport Sync's metadata pipe) */

#define FOURCC(s) ((uint32_t)(s)[0] << 24 | (uint32_t)(s)[1] << 16 | (uint32_t)(s)[2] << 8 | (uint32_t)(s)[3])

static char m_title[200], m_artist[200], m_album[200];      /* events thread only */
static int m_shown;

static void text(char *dst, size_t cap, const uint8_t *d, size_t n) { if (n >= cap) n = cap - 1; memcpy(dst, d, n); dst[n] = 0; }

static void screen_clear(void)
{
    if (!m_shown) return;
    m_shown = 0; m_title[0] = m_artist[0] = m_album[0] = 0;
    screen_music_meta("", "", ""); screen_music_progress(0, 0, 0, 1000); screen_music_art(NULL, 0);
}

static void event(uint32_t type, uint32_t code, const uint8_t *d, size_t n)
{
    char t[96];
    if (type == FOURCC("core")) {
        if (code == FOURCC("minm")) text(m_title, sizeof m_title, d, n);
        else if (code == FOURCC("asar")) text(m_artist, sizeof m_artist, d, n);
        else if (code == FOURCC("asal")) text(m_album, sizeof m_album, d, n);
        return;
    }
    if (type != FOURCC("ssnc")) return;
    if (code == FOURCC("pbeg")) {                       /* a session plays: whoever paused the last one, this is new */
        atomic_store(&hushed, 0); atomic_store(&paused_at, 0);
        fprintf(stderr, "airplay: session begins\n");
    } else if (code == FOURCC("prsm")) {                /* audio after a flush: the sender resumed */
        if (atomic_load(&hushed) && now_ms() - atomic_load(&hushed_at) > 1000) { atomic_store(&hushed, 0); atomic_store(&paused_at, 0); }
    } else if (code == FOURCC("pfls") || code == FOURCC("paus")) {
        atomic_store(&drop, 1);                         /* silent now, not after what is queued */
    } else if (code == FOURCC("pend")) {
        atomic_store(&drop, 1); screen_clear();
        fprintf(stderr, "airplay: session ended\n");
    } else if (code == FOURCC("pvol")) {                /* "airplay volume,volume,lowest,highest": the first, -30..0 dB, -144 muted */
        text(t, sizeof t, d, n);
        double db = atof(t);
        int pct = db <= -100 ? 0 : (int)((db + 30.0) / 0.3 + 0.5);
        pct = pct < 0 ? 0 : pct > 100 ? 100 : pct;
        atomic_store(&sender_pct, pct);
        pthread_mutex_lock(&core_lock);
        if (pct != core_volume()) core_set_volume(pct);
        pthread_mutex_unlock(&core_lock);
    } else if (code == FOURCC("clip") || code == FOURCC("acre") || code == FOURCC("daid")) {
        pthread_mutex_lock(&lock);
        char *dst = code == FOURCC("clip") ? client_ip : code == FOURCC("acre") ? active_remote : dacp_id;
        size_t cap = code == FOURCC("clip") ? sizeof client_ip : code == FOURCC("acre") ? sizeof active_remote : sizeof dacp_id;
        text(dst, cap, d, n);
        for (char *c = dst; *c; c++) if (!(*c >= '0' && *c <= '9') && !(*c >= 'a' && *c <= 'z') && !(*c >= 'A' && *c <= 'Z') && *c != '.' && *c != ':') { dst[0] = 0; break; }
        pthread_mutex_unlock(&lock);
    } else if (code == FOURCC("mden")) {
        m_shown = 1; screen_music_meta(m_title, m_artist, m_album);
    } else if (code == FOURCC("prgr")) {                /* "start/now/end" in RTP time */
        unsigned long long a, b, c; text(t, sizeof t, d, n);
        if (sscanf(t, "%llu/%llu/%llu", &a, &b, &c) == 3) {
            m_shown = 1;
            screen_music_progress(1, (long long)((uint32_t)(b - a)) * 1000 / RATE, (long long)((uint32_t)(c - a)) * 1000 / RATE, 1000);
        }
    } else if (code == FOURCC("PICT")) {
        if (n > 3 && d[0] == 0xff && d[1] == 0xd8) { m_shown = 1; screen_music_art(d, n); }   /* JPEG: what the screen decodes */
        else if (m_shown) screen_music_art(NULL, 0);
    }
}

#define META_MAX (3u << 20)             /* an item: artwork in base64, a megabyte or two at most */

static void *events_thread(void *arg)
{
    (void)arg;
    char p[PATH_MAX]; size_t cap = 65536, len = 0; char *buf = malloc(cap);
    in_state(p, sizeof p, ""); mkdir(p, 0700);
    in_state(p, sizeof p, "meta");
    struct stat st;
    if (lstat(p, &st) || !S_ISFIFO(st.st_mode)) { unlink(p); if (mkfifo(p, 0600)) fprintf(stderr, "airplay: no events (%s: %s)\n", p, strerror(errno)); }
    /* read and write: no end of file between Shairport Sync's openings of it, and no waiting for one here */
    int fd = open(p, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || !buf) { fprintf(stderr, "airplay: no events (%s)\n", strerror(errno)); return NULL; }
    for (;;) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, 1000) <= 0) { if (!atomic_load(&enabled)) screen_clear(); continue; }
        if (len + 1 >= cap) {
            if (cap >= META_MAX) { len = 0; continue; }                 /* no item is that long: start over */
            char *b = realloc(buf, cap * 2); if (!b) { len = 0; continue; }
            buf = b; cap *= 2;
        }
        ssize_t r = read(fd, buf + len, cap - 1 - len);
        if (r <= 0) continue;
        len += (size_t)r; buf[len] = 0;
        for (;;) {
            char *it = strstr(buf, "<item>"), *end = it ? strstr(it, "</item>") : NULL;
            if (!it) { if (len > 5) { memmove(buf, buf + len - 5, 6); len = 5; } break; }      /* "<item" may be cut */
            if (!end) { if (it != buf) { len -= (size_t)(it - buf); memmove(buf, it, len + 1); } break; }
            unsigned type = 0, code = 0;
            if (sscanf(it, "<item><type>%8x</type><code>%8x</code>", &type, &code) == 2) {
                char *d = strstr(it, "<data encoding=\"base64\">"); size_t n = 0;
                if (d && d < end) {
                    d += 24;
                    char *e = strstr(d, "</data>"), *w = d;
                    if (!e || e > end) e = end;
                    for (char *c = d; c < e; c++) if (*c > ' ') *w++ = *c;          /* line breaks out */
                    long k = b64_decode(d, (size_t)(w - d), (uint8_t *)d, (size_t)(w - d));     /* in place: shorter */
                    n = k > 0 ? (size_t)k : 0;
                }
                event(type, code, (const uint8_t *)(d ? d : ""), n);
            }
            end += 7;
            len -= (size_t)(end - buf); memmove(buf, end, len + 1);
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------- */

int airplay_enable(int set)
{
    if (set >= 0) atomic_store(&enabled, set != 0);
    return atomic_load(&enabled);
}

void airplay_start(void)
{
    pthread_t t;
    if (atomic_exchange(&started, 1)) return;
    if (!airplay_available()) {
        if (atomic_load(&enabled)) fprintf(stderr, "airplay: on, but this install has no receiver (%s)\n", binary());
        /* still started: an update may bring it, the setting then works without a restart */
    }
    pthread_create(&t, NULL, events_thread, NULL); pthread_detach(t);
    pthread_create(&t, NULL, dacp_thread, NULL); pthread_detach(t);
    pthread_create(&t, NULL, audio_thread, NULL); pthread_detach(t);
}
