# AirPlay receiver

`build.sh` builds [Shairport Sync](https://github.com/mikebrady/shairport-sync), the AirPlay receiver that
`src/hassmic/airplay.c` runs beside hassmic when the setting "AirPlay" is on (docs/GUIDE.md "AirPlay"):

    tools/airplay/build.sh host    build/airplay/host/shairport-sync   the PC's, for tests/fake_airplay.py
    tools/airplay/build.sh arm     build/airplay/arm/shairport-sync    every Echo's: `make airplay` copies it next to hassmic

## Why it is built this way

- **One static musl binary.** Shairport Sync is built on `pthread_cancel`, which bionic (the Echo's libc) does not have.
  musl has it, and a static musl binary needs nothing of Android or of the firmware, so one ARMv7 binary (about 500 KB)
  serves every model. It is cross-compiled with `zig cc` from PyPI's `ziglang` (`pyproject.toml`; `ZIG` names another).
- **Classic AirPlay ("AirPlay 1") only.** AirPlay 2 needs PTP on UDP 319 and 320 as root (NQPTP) and four more
  libraries.
- **Pinned sources.** The script fetches each project at a tag and checks that it is the commit named in the script;
  nothing of them is in this repository.

## Licences

| Project | Pinned | Licence |
| --- | --- | --- |
| [Shairport Sync](https://github.com/mikebrady/shairport-sync) | 4.3.7 (the version Music Assistant's AirPlay Receiver ships) | MIT-style, see its `LICENSES` file; it includes David Hammerton's ALAC decoder (`alac.c`, under its own MIT-style text), tinysvcmdns and tinyhttp |
| [popt](https://github.com/rpm-software-management/popt) | popt-1.19-release | MIT (Red Hat's text) |
| [libconfig](https://github.com/hyperrealm/libconfig) | v1.7.3 | LGPL-2.1-or-later |
| [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) | v2.28.10 | Apache-2.0 or GPL-2.0-or-later, at your choice |

libconfig is linked statically. This script and the pinned sources are what allow anyone to relink the binary against
another libconfig: fetch the sources with `build.sh`, change them, build again.

The binary carries the RSA private key of the AirPort Express that Shairport Sync ships in its source (`common.c`):
classic AirPlay senders encrypt the audio key to it. It is Shairport Sync's, not something this project added.
