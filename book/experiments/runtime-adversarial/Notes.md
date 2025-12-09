# Notes

- Re-ran `python run_adversarial.py` after adding file-write* rules to structural/path_edges SBPL and adding a network-outbound family (`net_outbound_allow`, `net_outbound_deny`).
  - Filesystem/mach families remain as before: struct_flat vs struct_nested match on read/write; path_edges shows `/tmp`→`/private/tmp` EPERM mismatches; mach literal/regex variants match.
  - Network: `net_outbound_allow` expected allow but ping to 127.0.0.1 exited with errno -6 under sandbox_runner (recorded as deny/mismatch). `net_outbound_deny` expected deny and recorded deny with errno -6 (match=true). Likely need a different network probe or allowance; ping may be blocked by sandbox or raw socket requirements.
