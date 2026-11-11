#!/usr/bin/env python3
"""AirPlay (airplay.c) end to end: build/hassmic-host runs the real Shairport Sync (build/airplay/host/shairport-sync,
tools/airplay/build.sh host), and a stand-in iPhone plays to it the way iOS does over classic AirPlay: RTSP with the
Apple-Challenge, the AES key under the AirPort Express RSA key, ALAC frames in AES-CBC over RTP, sync and timing
packets, the volume, a track's metadata, and a DACP remote control found by mDNS.

Checked: the setting starts and stops the receiver, what avahi is given to announce, the tone in the music output and
how soon after the first packet, the sender's volume on the Echo and the Echo's keys at the sender, a pause on the
phone silent at once, the action button pausing (silent before the phone reacts) and resuming, a skip, a sender that
ignores the remote control losing its session, the receiver killed and back, and one left behind by a hassmic that died.

Needs a network namespace of its own (tests/run.py gives one): UDP 5353 for the stand-in's mDNS answer."""
import asyncio, base64, os, re, secrets, signal, socket, struct, subprocess, sys, time
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from esphome_common import ROOT, check, run, until, port_open

SHAIRPORT = os.path.join(ROOT, "build", "airplay", "host", "shairport-sync")
RTSP_PORT = 28933
RATE, FPP = 44100, 352                                   # frames per packet, as every AirPlay sender's
LATENCY = 88200                                          # 2 s: what iOS asks of a classic AirPlay speaker
KEY_HELP, KEY_VOLUMEUP = 138, 115
NTP0 = 2208988800


def airport_key():
    """the AirPort Express key as Shairport Sync has it in its source: senders have its public half"""
    src = open(os.path.join(ROOT, "build", "airplay", "src", "shairport-sync", "common.c")).read()
    m = re.search(r'"(-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----)', src, re.S)
    pem = re.sub(r'"\s*\n\s*"', "", m.group(1)).replace("\\n", "\n")
    return serialization.load_pem_private_key(pem.encode(), None).public_key()


def ntp(t=None):
    t = time.time() if t is None else t
    return struct.pack(">II", int(t) + NTP0, int((t % 1) * 2 ** 32))


def alac(pcm):
    """one ALAC frame of stereo s16 samples, not compressed (the escape every decoder must take, and what Music
    Assistant's own AirPlay sender makes): 3 bits channels - 1, 16 unused, no size, no wasted bytes, "not compressed",
    the samples big-endian, the end tag 7"""
    bits = "001" + "0" * 16 + "0" + "00" + "1" + "".join(format(int(v) & 0xffff, "016b") for v in pcm.reshape(-1)) + "111"
    bits += "0" * (-len(bits) % 8)
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


class Phone:
    """the sender: one RTSP connection, the three UDP sockets, a DACP server and the mDNS answer that names its port"""
    def __init__(self, pub, dacp=True):
        self.pub, self.cseq = pub, 0
        self.dacp_id, self.remote = secrets.token_hex(8).upper(), str(secrets.randbelow(2 ** 31))
        self.aes_key, self.aes_iv = secrets.token_bytes(16), secrets.token_bytes(16)
        self.seq, self.ts = secrets.randbelow(60000), secrets.randbelow(2 ** 30)
        self.sending = None; self.freq = 440; self.phase = 0; self.first = True
        self.commands = []; self.react = 0.0; self.deaf = False; self.answer_dacp = dacp
        self.first_packet_at = None; self.closed = asyncio.Event()

    async def start(self):
        loop = asyncio.get_running_loop()
        self.r, self.w = await asyncio.open_connection("127.0.0.1", RTSP_PORT)
        self.ctrl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.ctrl.bind(("127.0.0.1", 0)); self.ctrl.setblocking(False)
        self.timing = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.timing.bind(("127.0.0.1", 0)); self.timing.setblocking(False)
        self.audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.audio.setblocking(False)
        loop.add_reader(self.timing, self.on_timing)
        self.http = await asyncio.start_server(self.on_dacp, "127.0.0.1", 0)
        self.dacp_port = self.http.sockets[0].getsockname()[1]
        self.mdns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.mdns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.mdns.bind(("0.0.0.0", 5353)); self.mdns.setblocking(False)
        loop.add_reader(self.mdns, self.on_mdns)

    def close(self):
        loop = asyncio.get_running_loop()
        if self.sending: self.sending.cancel()
        for s in (self.timing, self.mdns): loop.remove_reader(s)
        for s in (self.timing, self.mdns, self.ctrl, self.audio): s.close()
        self.http.close(); self.w.close()

    # ---- RTSP
    async def rtsp(self, method, headers=None, body=b"", uri=None):
        self.cseq += 1
        h = {"CSeq": self.cseq, "User-Agent": "AirPlay/377.40.00", "DACP-ID": self.dacp_id, "Active-Remote": self.remote,
             "Client-Instance": self.dacp_id}
        h.update(headers or {})
        if body: h["Content-Length"] = len(body)
        msg = f"{method} {uri or 'rtsp://127.0.0.1/3413821438'} RTSP/1.0\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
        self.w.write(msg.encode() + body); await self.w.drain()
        status = (await asyncio.wait_for(self.r.readline(), 5)).decode()
        got = {}
        while True:
            line = (await asyncio.wait_for(self.r.readline(), 5)).decode().strip()
            if not line: break
            k, _, v = line.partition(":"); got[k.strip().lower()] = v.strip()
        if int(got.get("content-length", 0)): await self.r.readexactly(int(got["content-length"]))
        return int(status.split()[1]) if status else 0, got

    async def watch(self):
        """the receiver closing the session shows as the connection's end"""
        while not self.r.at_eof(): await asyncio.sleep(0.05)
        self.closed.set()

    async def connect(self):
        challenge = secrets.token_bytes(16)
        st, h = await self.rtsp("OPTIONS", {"Apple-Challenge": base64.b64encode(challenge).decode().rstrip("=")}, uri="*")
        sig = base64.b64decode(h.get("apple-response", "") + "==")
        n = self.pub.public_numbers()
        clear = pow(int.from_bytes(sig, "big"), n.e, n.n).to_bytes(256, "big") if len(sig) == 256 else b""
        self.challenge_ok = st == 200 and clear[:2] == b"\x00\x01" and clear[-32:-16] == challenge
        rsa = self.pub.encrypt(self.aes_key, padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None))
        sdp = ("v=0\r\no=iTunes 3413821438 0 IN IP4 127.0.0.1\r\ns=iTunes\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
               "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 AppleLossless\r\na=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100\r\n"
               f"a=rsaaeskey:{base64.b64encode(rsa).decode().rstrip('=')}\r\na=aesiv:{base64.b64encode(self.aes_iv).decode().rstrip('=')}\r\n")
        st, _ = await self.rtsp("ANNOUNCE", {"Content-Type": "application/sdp"}, sdp.encode())
        if st != 200: return st
        st, h = await self.rtsp("SETUP", {"Transport": "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;"
                                          f"control_port={self.ctrl.getsockname()[1]};timing_port={self.timing.getsockname()[1]}"})
        if st != 200: return st
        t = dict(p.split("=") for p in h["transport"].split(";") if "=" in p)
        self.server_port, self.control_port = int(t["server_port"]), int(t["control_port"])
        st, _ = await self.rtsp("RECORD", {"Range": "npt=0-", "RTP-Info": f"seq={self.seq};rtptime={self.ts}"})
        return st

    async def volume(self, db): return (await self.rtsp("SET_PARAMETER", {"Content-Type": "text/parameters"}, f"volume: {db:.6f}\r\n".encode()))[0]

    async def metadata(self, title, artist, album):
        items = b"".join(tag + struct.pack(">I", len(v.encode())) + v.encode() for tag, v in ((b"minm", title), (b"asar", artist), (b"asal", album)))
        return (await self.rtsp("SET_PARAMETER", {"Content-Type": "application/x-dmap-tagged", "RTP-Info": f"rtptime={self.ts}"},
                                b"mlit" + struct.pack(">I", len(items)) + items))[0]

    async def flush(self): return (await self.rtsp("FLUSH", {"RTP-Info": f"seq={self.seq};rtptime={self.ts}"}))[0]

    # ---- UDP
    def on_timing(self):
        try: d, addr = self.timing.recvfrom(64)
        except OSError: return
        if len(d) >= 32 and d[1] == 0xd2: self.timing.sendto(b"\x80\xd3\x00\x07\x00\x00\x00\x00" + d[24:32] + ntp() + ntp(), addr)

    def sync(self):
        head = b"\x90\xd4\x00\x07" if self.first else b"\x80\xd4\x00\x07"
        self.ctrl.sendto(head + struct.pack(">I", (self.ts - LATENCY) & 0xffffffff) + ntp() + struct.pack(">I", self.ts), ("127.0.0.1", self.control_port))

    async def send(self):
        """the tone, a packet every 8 ms of it against the wall clock, a sync packet each second"""
        t0, sent, last_sync = time.monotonic(), 0, -1.0
        while True:
            now = time.monotonic() - t0
            if now - last_sync >= 1: self.sync(); last_sync = now
            while sent * FPP / RATE <= now:
                n = self.phase + np.arange(FPP); self.phase += FPP
                s = (np.sin(2 * np.pi * self.freq * n / RATE) * 8000).astype(np.int16)
                frame = alac(np.stack([s, s], axis=1))
                k = len(frame) // 16 * 16
                enc = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.aes_iv)).encryptor()
                payload = enc.update(frame[:k]) + enc.finalize() + frame[k:]
                head = struct.pack(">BBHII", 0x80, 0xe0 if self.first else 0x60, self.seq, self.ts, 0x12345678)
                self.audio.sendto(head + payload, ("127.0.0.1", self.server_port))
                if self.first_packet_at is None: self.first_packet_at = time.monotonic()
                self.first = False; self.seq = (self.seq + 1) & 0xffff; self.ts = (self.ts + FPP) & 0xffffffff; sent += 1
            await asyncio.sleep(0.004)

    def play(self, freq):
        self.freq, self.first = freq, True
        self.sending = asyncio.create_task(self.send())

    async def pause(self):
        if self.sending: self.sending.cancel(); self.sending = None
        return await self.flush()

    # ---- the remote control: DACP over HTTP, its port in an SRV record
    def on_mdns(self):
        try: d, addr = self.mdns.recvfrom(1500)
        except OSError: return
        name = f"iTunes_Ctrl_{self.dacp_id}._dacp._tcp.local"
        wire = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
        if not self.answer_dacp or len(d) < 12 or d[2] & 0x80 or wire.lower() not in d.lower(): return
        target = b"\x06iphone\x05local\x00"
        rr = wire + struct.pack(">HHIH", 33, 0x8001, 120, 6 + len(target)) + struct.pack(">HHH", 0, 0, self.dacp_port) + target
        self.mdns.sendto(d[:2] + b"\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" + rr, addr)

    async def on_dacp(self, r, w):
        req = (await r.readuntil(b"\r\n\r\n")).decode()
        path = req.split()[1]; remote = re.search(r"Active-Remote: (\S+)", req)
        self.commands.append((path, remote.group(1) if remote else None, time.monotonic()))
        w.write(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n" if self.deaf else b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        await w.drain(); w.close()
        if not self.deaf: asyncio.create_task(self.obey(path))

    async def obey(self, path):
        await asyncio.sleep(self.react)                              # a phone takes its time
        if path.endswith("/pause"): await self.pause()
        elif path.endswith("/play"): self.play(self.freq)
        elif path.endswith("/nextitem"): await self.pause(); self.play(self.freq + 220)
        elif "dmcp.device-volume=" in path: await self.volume(float(path.split("=")[1]))


def music(path):
    try: return np.fromfile(path, "<i2")[0::2].astype(float)
    except OSError: return np.zeros(0)


def loud(x, since=0):
    """sample index of the last audible sample at or after `since`, -1 if none"""
    nz = np.nonzero(np.abs(x[since:]) > 200)[0]
    return since + int(nz[-1]) if len(nz) else -1


def tone_hz(x):
    if len(x) < RATE // 4: return 0
    w = x[-RATE // 2:] if len(x) > RATE // 2 else x
    sp = np.abs(np.fft.rfft(w * np.hanning(len(w))))
    return float(np.argmax(sp)) * RATE / len(w)


async def main(e):
    out = e.env["HASSMIC_MUSIC"]; svc = os.path.join(e.state, "hassmic-airplay.service")
    pub = airport_key()
    row = next((s for s in e.page.state()["settings"] if s["name"] == "airplay"), None)
    check(row is not None and row["value"] in (0, False, "off"), "the page has the AirPlay setting, off")
    check(not port_open(RTSP_PORT) and not os.path.exists(svc), "off: no receiver, nothing announced")

    e.page.set(airplay="on")
    check(await until(lambda: port_open(RTSP_PORT) and os.path.exists(svc), 8), "switched on: the receiver listens and hands avahi a service file")
    text = open(svc).read() if os.path.exists(svc) else ""
    check("<type>_raop._tcp</type>" in text and f"<port>{RTSP_PORT}</port>" in text and re.search(r"<name>[0-9A-F]{12}@Echo Dot</name>", text) is not None
          and "<txt-record>et=0,1</txt-record>" in text and "<txt-record>tp=UDP</txt-record>" in text.replace("TCP,UDP", "UDP"),
          "announced: _raop._tcp under <id>@<the Echo's name>, with Shairport Sync's own TXT records")
    check(e.conf().get("airplay") == "on", "the setting is kept")

    p = Phone(pub); await p.start()
    st = await p.connect()
    check(st == 200 and p.challenge_ok, "a sender connects: Apple-Challenge signed with the AirPort key, ANNOUNCE (RSA + AES), SETUP, RECORD")
    check(await p.volume(-15.0) == 200 and await until(lambda: e.pv("volume") == 50, 3), "the sender's volume (-15 dB) is the Echo's: 50 %")
    asyncio.create_task(p.watch())
    p.play(440)
    check(await p.metadata("Blue in Green", "Miles Davis", "Kind of Blue") == 200, "a track's metadata is taken")
    check(await until(lambda: loud(music(out)) >= 0, 5), "the tone reaches the music output")
    delay = time.monotonic() - p.first_packet_at
    # Shairport Sync's own schedule for this sender: 2.32 s after the first packet (measured on its stdout alone); the
    # output gets each frame its queue (120 ms) ahead of that
    check(2.08 < delay < 2.36, f"in the output {delay:.2f} s after the first packet: when Shairport Sync wants it heard (2.32 s) less the output's queue")
    await asyncio.sleep(2.5)
    x = music(out); a = int(np.nonzero(np.abs(x) > 200)[0][0]); t = x[a:]
    rms = [float(np.sqrt(np.mean(t[i:i + 2205] ** 2))) for i in range(0, len(t) - 2205, 2205)]
    check(abs(tone_hz(t) - 440) < 3 and len(rms) > 30 and min(rms) > 2000 and max(rms) / min(rms) < 1.03,     # (its level: the Echo's volume)
          f"it is the tone, whole: {tone_hz(t):.0f} Hz, level {min(rms):.0f}..{max(rms):.0f} over {len(rms) * 0.05:.1f} s")
    check("airplay: playing" in e.log(), "the core knows music plays")

    # a pause on the phone: nothing of the two seconds it had sent ahead is played
    n0 = len(music(out)); await p.pause(); await asyncio.sleep(1.0)
    x = music(out); tail = (loud(x, n0) - n0) / RATE if loud(x, n0) >= 0 else 0
    check(tail < 0.15, f"paused on the phone: silent {max(tail, 0) * 1000:.0f} ms later")
    n0 = len(music(out)); p.play(660)
    check(await until(lambda: loud(music(out), n0) >= 0, 5), "resumed on the phone: plays again")
    await asyncio.sleep(1.5)
    check(abs(tone_hz(music(out)[n0:]) - 660) < 3, f"...the new tone ({tone_hz(music(out)[n0:]):.0f} Hz)")

    # the Echo's action button: silent at once, the phone told to pause; again: told to play
    p.react = 0.5
    n0 = len(music(out)); t0 = time.monotonic(); e.keyev(KEY_HELP, 1); e.keyev(KEY_HELP, 0)
    check(await until(lambda: any(c[0] == "/ctrl-int/1/pause" for c in p.commands), 3), "action button: the sender is told to pause, on the port its mDNS record names")
    c = next((c for c in p.commands if c[0] == "/ctrl-int/1/pause"), None)
    check(c is not None and c[1] == p.remote, "...with the session's Active-Remote")
    await asyncio.sleep(1.2)
    x = music(out); tail = (loud(x, n0) - n0) / RATE if loud(x, n0) >= 0 else 0
    check(tail < 0.2, f"...and the Echo is silent {max(tail, 0) * 1000:.0f} ms after the press, though the phone took 500 ms")
    check(await until(lambda: "airplay: stopped" in e.log(), 3), "the core knows it stopped")
    n0 = len(music(out)); e.keyev(KEY_HELP, 1); e.keyev(KEY_HELP, 0)
    check(await until(lambda: any(c[0] == "/ctrl-int/1/play" for c in p.commands), 3), "action button again: the sender is told to play")
    check(await until(lambda: loud(music(out), n0) >= 0, 5), "...and it plays again")

    # the Echo's volume key moves the phone's slider
    p.react = 0.0
    v0 = e.pv("volume"); e.keyev(KEY_VOLUMEUP, 1); e.keyev(KEY_VOLUMEUP, 0)
    check(await until(lambda: any("dmcp.device-volume=" in c[0] for c in p.commands), 3), "volume key: the sender is told the new volume")
    v1 = e.pv("volume"); c = next((c for c in p.commands if "dmcp.device-volume=" in c[0]), None)
    check(c is not None and v1 > v0 and abs(float(c[0].split("=")[1]) - (-30 + v1 * 0.3)) < 0.01, f"...{v1} % as AirPlay's dB")
    await asyncio.sleep(0.5)
    check(e.pv("volume") == v1, "...and its answer leaves the Echo's volume where the key put it")

    # the button twice: next track
    e.page.set(multi_press="on")
    await asyncio.sleep(1.0); n0 = len(music(out)); f0 = p.freq
    for _ in range(2): e.keyev(KEY_HELP, 1); e.keyev(KEY_HELP, 0); await asyncio.sleep(0.15)
    check(await until(lambda: any(c[0] == "/ctrl-int/1/nextitem" for c in p.commands), 3), "button twice: the sender is told to skip")
    await asyncio.sleep(3.5)
    check(abs(tone_hz(music(out)[n0:]) - (f0 + 220)) < 3, f"...and the next track plays ({tone_hz(music(out)[n0:]):.0f} Hz)")
    e.page.set(multi_press="off")

    # a sender that does not take the pause: silent all the same, and its session ends
    p.deaf = True; n0 = len(music(out)); e.keyev(KEY_HELP, 1); e.keyev(KEY_HELP, 0)
    try: await asyncio.wait_for(p.closed.wait(), 6); gone = True
    except asyncio.TimeoutError: gone = False
    check(gone, "a sender that refuses the pause loses its session")
    x = music(out); tail = (loud(x, n0) - n0) / RATE if loud(x, n0) >= 0 else 0
    check(tail < 0.2, f"...and was silent {max(tail, 0) * 1000:.0f} ms after the press")
    p.close()
    check(await until(lambda: port_open(RTSP_PORT) and os.path.exists(svc), 8), "the receiver is back for the next sender")

    # the receiver dies (its decoder does on some malformed streams): back by itself
    pid = int(open(os.path.join(e.state, "airplay", "pid")).read())
    os.kill(pid, signal.SIGKILL)
    check(await until(lambda: not os.path.exists(svc), 3), "the receiver killed: its announcement goes")
    check(await until(lambda: port_open(RTSP_PORT) and os.path.exists(svc), 8), "...and it is started again")
    p = Phone(pub); await p.start()
    check(await p.connect() == 200, "a sender connects to the new one")
    n0 = len(music(out)); p.play(550)
    check(await until(lambda: loud(music(out), n0) >= 0, 5), "...and plays")

    # switched off while it plays
    e.page.set(airplay="off")
    check(await until(lambda: not port_open(RTSP_PORT) and not os.path.exists(svc), 5), "switched off: no receiver, nothing announced")
    await asyncio.sleep(0.3); n0 = len(music(out)); await asyncio.sleep(0.5)
    check(loud(music(out), n0) < 0, "...and silent")
    p.close()

    # one left behind by a hassmic that died holds the port: ended by the next start
    orphan = subprocess.Popen([SHAIRPORT, "-c", os.path.join(e.state, "airplay", "shairport-sync.conf")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              env=dict(os.environ, PATH=os.path.join(e.state, "airplay", "bin") + ":" + os.environ["PATH"], HASSMIC_AIRPLAY_MDNS=svc), start_new_session=True)
    await until(lambda: port_open(RTSP_PORT), 5)
    with open(os.path.join(e.state, "airplay", "pid"), "w") as f: f.write(f"{orphan.pid}\n")
    e.page.set(airplay="on")
    check(await until(lambda: orphan.poll() is not None, 5), "a receiver left over from an earlier hassmic is ended")
    check(await until(lambda: port_open(RTSP_PORT) and os.path.exists(svc) and "receiver started" in e.log().split("an earlier receiver")[-1], 8), "...and a new one runs")
    e.page.set(airplay="off")
    await until(lambda: not port_open(RTSP_PORT), 5)


if __name__ == "__main__":
    if not os.access(SHAIRPORT, os.X_OK):
        print("building Shairport Sync for this PC (tools/airplay/build.sh host)...", flush=True)
        if subprocess.run([os.path.join(ROOT, "tools", "airplay", "build.sh"), "host"]).returncode or not os.access(SHAIRPORT, os.X_OK):
            print("FAIL Shairport Sync could not be built: tools/airplay/build.sh host (needs git, autoconf, automake, libtool and the network)")
            print("FAILED"); sys.exit(1)
    import tempfile
    run(main, (16980, 16981, 16982, 16983, 16984), log=True,
        extra_env={"HASSMIC_SHAIRPORT": SHAIRPORT, "HASSMIC_MUSIC": tempfile.mktemp(suffix=".music.raw")})
