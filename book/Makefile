.DEFAULT_GOAL := test

SWIFT ?= swift
REPO_ROOT := $(abspath $(CURDIR)/..)

# Prefer the repo venv python if it exists; allow override via `make PYTHON=...`
VENV_PY := $(REPO_ROOT)/.venv/bin/python
ifeq ($(wildcard $(VENV_PY)),)
PYTHON ?= python3
else
PYTHON ?= $(VENV_PY)
endif

.PHONY: test ci validate swift clean build venv-check

test: ci

ci:
	@echo "Running unified CI harness..."
	PYTHONPATH=$(REPO_ROOT) SWIFT=$(SWIFT) $(PYTHON) ci.py

clean:
	rm -rf graph/.build graph/.swiftpm graph/.module-cache \
	       __pycache__ */__pycache__

build:
	@echo "Running Python tests and Swift build..."
	CLANG_MODULE_CACHE_PATH=$(CURDIR)/graph/.module-cache \
	SWIFTPM_MODULECACHE_OVERRIDE=$(CURDIR)/graph/.module-cache \
	PYTHONPATH=$(REPO_ROOT) SWIFT=$(SWIFT) $(PYTHON) ci.py

# Optional subtargets to run pieces directly.
validate:
	PYTHONPATH=$(REPO_ROOT) $(PYTHON) -c "import ci; ci.run_python_harness()"

swift:
	PYTHONPATH=$(REPO_ROOT) SWIFT=$(SWIFT) $(PYTHON) -c "import ci; ci.run_swift_build()"
