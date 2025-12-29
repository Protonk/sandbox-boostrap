"""Shared helpers for Ghidra scripts.

This package hosts lightweight utilities that are safe to import from Jython
scripts running inside Ghidra. Keep dependencies minimal and avoid Python
features that Jython (Python 2.x) does not support.
"""

# Ghidra's Jython runtime lags modern CPython; avoid f-strings and type-only imports here.
# Centralizing helpers here keeps scripts shorter and reduces copy/paste drift.
