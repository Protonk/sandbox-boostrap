# lifecycle-lockdown (Notes)

- Run `python3 book/experiments/lifecycle-lockdown/run_lockdown.py --help` to see knobs and output layout.
- Keep failures as first-class: non-zero exit codes, missing tools, or unexpected “no-op” results should be recorded in `Report.md` as bounded outcomes.
- Lane isolation runs:
  - `python3 -m book.api.runtime run --plan book/experiments/lifecycle-lockdown/plan.json --channel launchd_clean --out book/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce`
  - `SANDBOX_LORE_PREFLIGHT_FORCE=1 python3 -m book.api.runtime run --plan book/experiments/lifecycle-lockdown/plan.json --channel launchd_clean --out book/experiments/lifecycle-lockdown/out/runtime/launchd_clean_force`
- In this Codex harness, `launchd_clean` needed an unsandboxed run (otherwise `launchctl bootstrap` failed with exit status `5`); see the committed runtime bundles under `out/runtime/` for stage+lane details.
