# SBPL parameters

- `(param "...")` lets one SBPL profile embed switches that are set at compile/evaluation time, producing different rule graphs without editing the text.
- Parameters differ from entitlements (signature metadata) and extensions (runtime tokens): params are static inputs baked into the compiled profile.
- Many system profiles use params to specialize behavior per target or build, which makes static analysis trickier because the effective policy depends on how params were set.
- Tooling like `sandbox-exec -D` exposes params only partially on macOS; be clear about what works on your system when demonstrating parameterized rules.
