# Metadata Runner

Role: Swift helper that applies an SBPL profile (SBPL text or blob) and issues
metadata-related syscalls (stat, getattrlist, chmod, utimes, etc.) while
emitting a JSON record of the outcome.

Use when: you need a low-noise runner for `file-read-metadata` and metadata
write proxy operations under a sandbox profile.

World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

Build:

```sh
book/api/runtime/native/metadata_runner/build.sh
```

Usage example:

```sh
./metadata_runner --sbpl /tmp/profile.sb --op file-read-metadata --path /private/tmp/foo
```
