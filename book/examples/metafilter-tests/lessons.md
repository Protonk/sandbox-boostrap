# Metafilters in practice

- `require-any/all/not` are SBPL combinators that compile into specific graph shapes even though the binary format has no explicit metafilter opcode (substrate/Appendix.md §5).
- Small profiles make it easier to see how OR/AND/NOT change behavior: deny if any literal matches, deny only when multiple predicates are true, or deny the inverse of a predicate.
- sandbox-exec is a convenient harness for experimenting, but the same logic applies to compiled profiles parsed from the kernelcache or system `.sb` files.
- Misunderstanding metafilter structure is a common source of “why was this path denied?” confusion; tracing the boolean structure first prevents surprises.
