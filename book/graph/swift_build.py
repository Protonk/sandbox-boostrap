#!/usr/bin/env python3
"""
Run `swift build` and suppress the noisy XCTest path warning that appears
when only Command Line Tools are installed (no full Xcode platform path).
Passes through stdout/stderr otherwise and returns the original exit code.
"""

import os
import subprocess
import sys


def main() -> int:
    cmd = [os.environ.get("SWIFT_BIN", "swift"), "build", "--disable-sandbox"]
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
