# Containers and redirects

- App containers move data under `~/Library/Containers/...` (and Group Containers) while user-facing paths may be symlinks; Seatbelt resolves the real path before evaluating `subpath`/`regex` filters.
- Symlinks do not circumvent sandbox checks—the resolved target path is what the policy graph sees (see substrate/Appendix.md path filter notes).
- Understanding container layout helps interpret file rules in decoded profiles and explains why “same-looking” paths behave differently for sandboxed vs unsandboxed processes.
