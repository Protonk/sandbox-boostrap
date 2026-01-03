# Frida Attach Helper

Role: small signed helper that embeds Python and runs `book.api.frida.native.attach_helper.driver` to perform Frida attach inside the signed process.

World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

Build:

```sh
./build.sh
```

Sign (ad-hoc example):

```sh
codesign --force --sign - --entitlements entitlements.plist frida_attach_helper
```

Usage (direct):

```sh
./frida_attach_helper \
  --python-exec /opt/homebrew/bin/python3.14 \
  --python-path /path/to/repo \
  --python-path /path/to/venv/lib/python3.14/site-packages \
  -- \
  --pid 1234 \
  --script book/api/frida/hooks/smoke.js \
  --events /tmp/frida/events.jsonl \
  --meta /tmp/frida/meta.json
```

The helper prints JSON lines to stdout (ready/finalize/close responses) and reads JSON commands on stdin.
