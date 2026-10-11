# axtypes: the type system in Python

A small reference implementation of the calculus, over the execution graphs
that Clou exports. The C++ engine in `src/axtypes/` implements the same rules
and is tested against the same case studies.

| File | Contents |
|---|---|
| `lattice.py` | two-point lattice and pair types `<a,t>` with `a <= t` |
| `graph.py` | events and the relations `rf`, `rfx`, `data`, `addr`, `ctrl` |
| `typecheck.py` | event typing, observation typing, refinement, containment |
| `cases.py` | the paper's four case studies (Spectre-v1, SLH, v4, RSB) as graphs |
| `loader.py` | loads Clou's `cloupy_graph_*.json` exports and seeds them |
| `check.py` | command line: containment check on exported graphs |
| `render.py` | typed graph as Graphviz DOT |
| `tests/` | unit tests, and tests on witness graphs exported by Clou (`tests/data/`) |

```sh
cd tools/axtypes
PYTHONPATH=. python3 -m unittest discover -s tests
python3 check.py /path/to/clou-output-dir
```

Clou's benchmarks have no secrecy labels. `loader.py` seeds a transient read
that has an address predecessor as `<L,H>`: such a read can be steered out of
bounds and may return a secret. With `--no-seed` every graph is contained.
