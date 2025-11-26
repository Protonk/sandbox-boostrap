# SB sample pipeline

- Compiles `sample.sb` via libsandbox and now routes header/section parsing through the shared Axis 4.1 ingestion layer (`concepts/cross/profile-ingestion/ingestion.py`) instead of local ad hoc parsing.
- The ingestion layer currently targets the modern graph-based format; other examples (e.g., `sbdis/`) can be migrated to reuse it later.
