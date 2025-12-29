#@category Sandbox
"""
Pre-script to disable x86-only analyzers on ARM64 kernelcache runs.

Ghidra's analyzer pipeline can still enable x86 analyzers even when the program
is ARM64. Disabling them here keeps headless imports fast and avoids noisy logs.
"""

from ghidra.program.model.listing import Program

TARGET_ANALYZERS = [
    "X86 Constant Reference Analyzer",
    "X86 Emulate Instruction Analyzer",
]


def run():
    opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
    for name in TARGET_ANALYZERS:
        if opts.contains(name):
            # Analyzer names are string keys in Ghidra's analysis options.
            opts.setBoolean(name, False)
            print("Disabled analyzer: %s" % name)
        else:
            print("Analyzer not present: %s" % name)


# Ghidra scripts execute run() when loaded; keep this explicit for clarity.
run()
