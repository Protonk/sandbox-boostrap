#!/usr/bin/env python3
"""
Run `swift build` and suppress the noisy XCTest path warning that appears
when only Command Line Tools are installed (no full Xcode platform path).
Passes through stdout/stderr otherwise and returns the original exit code.
"""

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    graph_root = Path(__file__).resolve().parent
    default_cache = graph_root / ".build" / "swiftpm-cache"
    cache_path = Path(os.environ.get("SWIFTPM_CACHE_PATH", str(default_cache)))
    default_config = graph_root / ".build" / "swiftpm-config"
    config_path = Path(os.environ.get("SWIFTPM_CONFIG_PATH", str(default_config)))
    default_security = graph_root / ".build" / "swiftpm-security"
    security_path = Path(os.environ.get("SWIFTPM_SECURITY_PATH", str(default_security)))
    cache_path.mkdir(parents=True, exist_ok=True)
    config_path.mkdir(parents=True, exist_ok=True)
    security_path.mkdir(parents=True, exist_ok=True)

    cmd = [
        os.environ.get("SWIFT_BIN", "swift"),
        "build",
        "--disable-sandbox",
        "--cache-path",
        str(cache_path),
        "--config-path",
        str(config_path),
        "--security-path",
        str(security_path),
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()

    sys.stdout.write(out)

    skip = False
    for line in err.splitlines():
        if "could not determine XCTest paths" in line:
            skip = True
            continue
        if skip and line.strip() == "":
            skip = False
            continue
        if skip:
            continue
        sys.stderr.write(line + "\n")

    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
