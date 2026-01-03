# Hold Open

Role: minimal keepalive helper that blocks until signaled, with an optional wait barrier.

Use when: you need a stable PID for sandbox_check or attach workflows outside PolicyWitness.

Build:

```sh
./build.sh
```

Usage:

```sh
./hold_open
./hold_open --wait fifo:auto
./hold_open --wait exists:/tmp/hold_open.trigger
./hold_open --max-seconds 30
```

Output: JSON lines with `kind` values `hold_open_ready`, `hold_open_triggered`, and `hold_open_exit`.
