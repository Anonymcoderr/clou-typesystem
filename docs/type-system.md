# Type-system engine

This repository extends Clou with a second detection engine. Clou's own
detector searches for one transmitter at a time with an SMT solver. The type
engine builds one over-approximated execution graph per function, types it, and
reports every checked observation whose type is unstable.

Select it with `CLOU_AXTYPES_ENGINE=1`. Without that variable Clou behaves as
before.

## Where things are

| Path | Contents |
|---|---|
| `src/axtypes/` | Lattice, graph, event and observation typing, refinement, containment. Plain C++, no LLVM or Z3. |
| `src/aeg/axtypes_engine.cc` | Builds the graph from Clou's AEG, seeds it, discharges refinement facts, reports transmitters. |
| `tools/axtypes/` | The same calculus in Python, with the paper's four case studies as tests. |
| `scripts/litmus-table.sh` | Both engines on the PHT and STL litmus suites. |
| `scripts/casestudy/` | The OpenSSL bugs and constant-time crypto. |
| `scripts/soundness/` | Mutation tests and differential fuzzing against the SMT engine. |

## The graph

Events are the nodes of Clou's AEG. An `addr`, `data` or `ctrl` edge is kept
unless its existence condition simplifies to false, and an event counts as
transient unless it provably is not.

`rf` and `rfx` are not stored in the AEG. Deciding one exactly needs a walk over
all other writes, so every same-location write/read pair in admissible order is
kept instead. This is a superset of the exact relation at constant cost per
pair, and extra edges can only raise types. `CLOU_AXTYPES_EXACT_COM=1` selects
the exact check.

For Spectre-v1 the pass first promotes stack slots to SSA (register
elimination), so that `-O0` spills and reloads do not become memory events.
Spectre-v4 runs are not promoted, because there a spill and reload is the store
forward under analysis. Clou's SMT detector always sees the original IR.
`CLOU_NO_MEM2REG=1` turns promotion off and `CLOU_MEM2REG=1` forces it on.

## Seeds

Clou's benchmarks carry no secrecy annotations. Following Clou's threat model, a
transient read whose address is not a fixed location may return any value in
memory, so its value is seeded `<L,H>`.

- `CLOU_AXTYPES_UNGATED=1` seeds every such read. The case studies use this.
- By default only reads whose index is attacker-controlled, according to Clou's
  taint analysis, are seeded.

Whether an address is fixed is decided from the `addr` edges and from the
address operand itself. After register elimination an index is often a function
argument, which is not an event, so the operand has to be inspected directly.
`CLOU_AXTYPES_RESIDUAL_SEED=0` disables that inspection.

## Refinement

A fact lowers the target component of one address observation to its
architectural component. Every discharge is logged (`REFINE-FACT: ...`). If
refinement ever added a flag, the unrefined result is used.

| Procedure | Discharges when | Status |
|---|---|---|
| known-bits | the address stays within one cache line of a global or stack object | checked |
| SLH | the address slice contains the marker `__clou_slh*` and the access is transient | trusted |
| allowlist | the location is listed in `CLOU_CT_SAFE=line:col,...` | trusted |

Known-bits refuses an index that is merely bounded (`B[s & 0xff]` spans many
cache lines) and a constant offset from a loaded pointer (`p->f` lies wherever
`p` points).

## What is reported

Unstable address observations are reported as address transmitters. Unstable
control observations are reported when control transmitters are requested, with
`--spectre-v1=mode=branch-predicate` or a `ctrl` entry in `--deps`. Clou draws
`ctrl` edges from the deciding load, not from a branch node, and the load's type
then stands for the predicate type.

With register elimination there are no events for promoted stack slots. The SMT
engine sees the original IR and can report control transmitters on them.

## Running it

Build as described in the top-level README. The scripts look for the plugin in
`build-clean/src/libclou.so` and take another path as their first argument.

```sh
cd tools/axtypes && PYTHONPATH=. python3 -m unittest discover -s tests
(cd build-clean && ctest)
scripts/litmus-table.sh
scripts/axtypes-refine-test.sh
python3 scripts/soundness/metamorphic.py
scripts/casestudy/validate_openssl.sh     # after fetch_libs.sh and configure_libs.sh
scripts/casestudy/precision_crypto.sh
```

`litmus-table.sh` should end with these totals:

| Suite | SMT | Type engine | SMT locations not flagged |
|---|---|---|---|
| PHT (15 tests), address transmitters | 14 | 15 | 0 |
| STL (13 tests) | 16 | 32 | 0 |

## Limits

- Clou does not construct Spectre-RSB graphs. The RSB case study is a hand-built
  graph in the unit tests.
- Only the detection step is solver-free. Building the AEG still uses Clou's
  alias analysis and Z3 simplification.
- The type engine is not extracted from the Isabelle development. The fuzzing
  and mutation tests compare it against Clou's SMT detector.
