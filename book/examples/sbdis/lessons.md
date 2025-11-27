# sbdis legacy disassembler

- Now uses the shared ingestion layer (`book/concepts/validation/profile_ingestion.py`) for header and section slicing of legacy decision-tree blobs; the node/handler decoding logic remains local.
- Still targets the early format described in `sb_format.txt`; modern graph-based blobs should be decoded by newer tools.
