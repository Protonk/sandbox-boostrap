#@category Sandbox
"""
Pre-script to disable x86-only analyzers on ARM64 kernelcache runs.
Useful when headless does not support -analysisProperties.
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
            opts.setBoolean(name, False)
            print("Disabled analyzer: %s" % name)
        else:
            print("Analyzer not present: %s" % name)


run()
