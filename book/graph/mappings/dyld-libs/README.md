Dyld slice manifest for Sonoma 14.4.1 (23E224) host baseline.  
`manifest.json` records size/sha256 and anchor symbols for trimmed dyld slices used by vocab/encoder work.  
`check_manifest.py` recomputes hashes and verifies symbol addresses; guardrailed by `book/tests/planes/graph/test_dyld_libs_manifest.py`.
