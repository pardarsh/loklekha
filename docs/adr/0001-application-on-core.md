# ADR 0001: Build Loklekha only from pardarsh-core primitives

Status: accepted (2026-10-09)

Loklekha defines no record types of its own. App concepts map to core kinds
plus `loklekha.*` extensions and `loklekha:*` extension kinds, relations and
event tags (see `src/vocab.rs`). The status lives in an extension field and
changes only through the transition command, tagged `loklekha:status_change`.
The generic edit path is not exposed, and unknown request fields are
rejected, so clients cannot set a status directly.

Consequence: anything Loklekha records can be exported, verified and imported
by any pardarsh-core consumer, and the core stays free of issue workflow.
