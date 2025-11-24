# Regex to Graphviz

- Converts AppleMatch regex blobs (`.re`) from compiled sandbox profiles into Graphviz `.dot` files for visualization.
- Inputs should come from profile regex tables as described in `guidance/Appendix.md` (“Regular Expressions and Literal Tables”), not from arbitrary regex formats.
- Useful alongside tools like `resnarf`/`sbdis` that extract or reference regex entries from legacy or modern profiles.
