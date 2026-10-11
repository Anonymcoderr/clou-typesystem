# Soundness tests

These check that the type engine does not miss what Clou's SMT detector finds.
They assert a superset relation only; precision is not tested here. All take
`--plugin PATH` and default to `build-clean/src/libclou.so`.

| Script | What it does | What must hold |
|---|---|---|
| `metamorphic.py` | leak-preserving variants of the v1 and v4 gadgets, a control-leak family (Kocher example 10) run in `mode=branch-predicate`, and a few secure controls | every leaking variant is flagged |
| `difffuzz.py` | random Spectre-v1-shaped functions, both engines on the same IR | per function, every SMT transmitter is reported; violations are minimized |
| `oracle_fuzz.py` | the same generator, but the SMT detector runs on the original IR and the type engine with register elimination | per function, every source location the SMT detector reports is flagged; `--mode branch-predicate` generates and checks control leaks |
| `graph_complete.py` | SMT witnesses against the over-approximated graph | every witness edge is in the graph |

```sh
python3 scripts/soundness/metamorphic.py
python3 scripts/soundness/difffuzz.py -n 300 --seed 0
python3 scripts/soundness/graph_complete.py
python3 scripts/soundness/oracle_fuzz.py -n 1000 --seed 1
python3 scripts/soundness/oracle_fuzz.py -n 500 --seed 1 --mode branch-predicate
```

`difffuzz.py` and `graph_complete.py` compare instructions and node ids, so
they run the type engine without register elimination; `oracle_fuzz.py` is the
test that covers it.

`oracle_fuzz.py` prints how many locations the oracle reported, so a pass on a
run with no oracle findings is visible as such. The scripts leave their per-run
output directories under `$TMPDIR`; use a directory on disk for long runs.
