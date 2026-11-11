/* AirPlay receiver (optional, setting `airplay`, off by default): Shairport Sync run beside hassmic, its audio played
 * on the music stream.  See airplay.c. */
#ifndef AIRPLAY_H
#define AIRPLAY_H
int  airplay_available(void);           /* this install has the receiver (shairport-sync next to hassmic) */
void airplay_start(void);               /* the threads; the receiver itself runs only while the setting is on */
int  airplay_enable(int set);           /* the setting: 0/1, -1 reads.  Any thread, no lock */
int  airplay_button(int resume);        /* action button: 0 = pause the sender if it plays, 1 = resume one the Echo paused.
                                           1 = the press was used */
int  airplay_skip(int dir);             /* the button twice (+1: next) or three times (-1: previous): 1 = sent */
int  airplay_stop(void);                /* "<wake word>, stop": 1 = it played and is silent now (the button resumes it) */
void airplay_pause(void);               /* another source started, a call: silent at once, the sender asked to pause */
void airplay_volume_changed(int percent);   /* the Echo's volume changed: the sender's slider follows */
/* argv[0] "avahi-publish-service": Shairport Sync's external mDNS backend runs a program of that name with what it
 * wants announced; ours (a link to hassmic) writes it as a service file for the stock avahi and stays until told to
 * go.  main() hands over to it first thing.  Returns the exit code */
int  airplay_publish(int argc, char **argv);
#endif
