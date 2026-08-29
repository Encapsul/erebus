# SISR Model Benchmark — Real Engine Measurement

_Measured via `erebus-core/examples/sisr_bench.rs` (drives `SisrEngine::apply_update_with_stats`)._

## Scenario

| Property | Value |
|---|---|
| Payload size | 613 MB |
| Changed region | 6.13 MB (1.0%) |
| Content-defined chunk target | 64 KiB |

## Results (measured through the engine)

| Metric | Full re-download | SISR delta | Savings |
|---|---|---|---|
| Transfer size | 613 MB | 6.27 MB | 99.0% |
| Reused chunks | — | 5022 | — |
| Fetched chunks | — | 58 | — |

The delta is the sum of only the chunks `SisrEngine` actually fetched;
unchanged chunks are copied from the running binary and never hit the
network. Because content-defined chunking may span the changed region,
the fetched bytes can slightly exceed the literal changed bytes.

