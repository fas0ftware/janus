# Janus

A command-line TCP connect port scanner for Linux, written in C11 with plain POSIX sockets.

Named after Janus, the Roman god of gates and doorways. Ports are doors.

> **Authorized use only.** Scan only your own devices, your own network, or hosts
> you have explicit written permission to test.

## Status

Work in progress. Full documentation will be added in a later milestone.

## Build

```sh
make        # release build -> ./janus
make debug  # sanitizer build -> ./janus-debug
make test   # run tests
make clean  # remove build output
```
