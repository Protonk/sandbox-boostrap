# Notes

- Re-ran `python run_adversarial.py` after adding file-write* rules to structural/path_edges SBPL and adding a network-outbound family (`net_outbound_allow`, `net_outbound_deny`).
  - Filesystem/mach families remain as before: struct_flat vs struct_nested match on read/write; path_edges shows `/tmp`→`/private/tmp` EPERM mismatches; mach literal/regex variants match.
  - Network: first ping-based loopback probe mismatched on allow (errno -6). Switched to a TCP loopback probe with an in-harness listener; `net_outbound_allow` still records deny (unexpected_deny), `net_outbound_deny` records deny (match). Network coverage remains partial until a clearer probe succeeds.
