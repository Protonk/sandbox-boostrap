# Experiment: sandbox-init-params

## AIM (initial)

Understand how `libsystem_sandbox` and related userland entry points (e.g., `sandbox_init`, `sandbox_init_with_parameters`, `sandbox_apply`) on Sonoma 14.4.1:
- Resolve and call the libsandbox compile entry points (`sandbox_compile_*`),
- Represent compiled profiles and parameters as handles/structures, and
- Hand compiled profiles and parameters to `__sandbox_ms`.

This experiment starts where `libsandbox-encoder` stopped: it treats the compiled `sb_buffer*` from libsandbox as a black-box “profile handle” and focuses on the `sandbox-init` / parameter plumbing and syscall argument packing.

## Relationship to libsandbox-encoder

- Depends on the closed experiment at `book/experiments/libsandbox-encoder/` for:
  - The definition of the compiled profile blob and its PolicyGraph layout.
  - The identification of encoder sites in `libsandbox.1.dylib` (`_emit_*`, `_record_condition_data`, `_compile`, builder+0xe98).
- Does **not** redo PolicyGraph decoding or field2 layout; those results are assumed as given.

## Next steps (to be designed)

- Follow the Experimenter role guidance in `AGENTS.md` to design phases, probes, and documentation layout for this experiment.
- Decide which questions about `sandbox_init*` / parameters / `__sandbox_ms` are in scope for the first iteration.
