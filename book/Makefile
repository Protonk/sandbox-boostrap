.DEFAULT_GOAL := test

PYTHON ?= python3
SWIFT ?= swift
REPO_ROOT := $(abspath $(CURDIR)/..)

.PHONY: test ci validate swift

test: ci

ci:
	@echo "Running unified CI harness..."
	PYTHONPATH=$(REPO_ROOT) SWIFT=$(SWIFT) $(PYTHON) ci.py

clean:
	rm -rf graph/.build graph/.swiftpm graph/.module-cache \
	       graph/out/ci-stamps/python-harness.json \
	       graph/out/ci-stamps/swift-build.json \
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
