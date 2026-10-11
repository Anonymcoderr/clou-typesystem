"""Render a typed execution graph as Graphviz DOT."""
from __future__ import annotations

from lattice import Ty, PUBLIC, LEAK, SECRET
from graph import Graph, READ, WRITE, BRANCH, SPECIAL
from typecheck import Typing, cache_observer_obsset, obs_type

_FILL = {
    (False, False): "#e6f5e6",
    (False, True): "#ffd6d6",
    (True, True): "#e8e8e8",
}
_EDGE = {
    "rf":   ('#c0392b', "solid",  "rf"),
    "rfx":  ('#e67e22', "dashed", "rfx"),
    "data": ('#2980b9', "solid",  "data"),
    "addr": ('#8e44ad', "bold",   "addr"),
    "ctrl": ('#7f8c8d', "dotted", "ctrl"),
}


def _short(name: str) -> str:
    name = name.split("!dbg")[0].strip()
    return (name[:40] + "…") if len(name) > 41 else name


def to_dot(g: Graph, title: str, refine=None, focus=False) -> str:
    ty = Typing(g) if refine is None else Typing(g, refine)
    leaks = {}
    for (obs, eid) in cache_observer_obsset(g):
        t = obs_type(ty, obs, eid)
        if not t.stable():
            leaks.setdefault(eid, []).append(obs)

    keep = set(g.events)
    if focus:
        connected = set()
        for rel in ("rf", "rfx", "data", "addr", "ctrl"):
            for (s, d) in getattr(g, rel):
                connected.add(s); connected.add(d)
        keep = {eid for eid, e in g.events.items()
                if eid in connected or eid in leaks}

    out = ['digraph G {', '  rankdir=TB;', '  node [shape=box, style="rounded,filled", '
           'fontname="Helvetica", fontsize=10];', '  edge [fontname="Helvetica", fontsize=8];',
           f'  labelloc="t"; label="{title}";']

    for e in g.events.values():
        if e.id not in keep:
            continue
        gamma = ty.gamma[e.id]
        lines = [f"{e.id}: {_short(e.name) or e.kind}"]
        shape = "box"
        if e.kind == SPECIAL:
            shape = "diamond"
            lines = [f"{_short(e.name) or ('⊤/⊥')}"]
        else:
            lines.append(f"Γ*={gamma}")
            if e.kind == BRANCH:
                lines.append(f"Pred={ty.PredTy(e.id)}")
            if e.is_memory():
                at = ty.AddrTy(e.id)
                lines.append(f"Addr={at}")
                ct = ty.CtrlTy(e.id)
                if not ct.stable():
                    lines.append(f"Ctrl={ct}")
        transient = " (S)" if e.transient else ""
        fill = _FILL.get((gamma.a, gamma.t), "#ffffff")
        pen = "1"
        color = "#333333"
        if e.id in leaks:
            pen = "3"
            color = "#c0392b"
            lines.append("⚠ LEAK: " + ",".join(leaks[e.id]))
            fill = "#ffb3b3"
        label = "\\n".join(lines).replace('"', "'") + transient
        out.append(f'  n{e.id} [label="{label}", shape={shape}, fillcolor="{fill}", '
                   f'color="{color}", penwidth={pen}];')

    for rel in ("rf", "rfx", "data", "addr", "ctrl"):
        col, style, lab = _EDGE[rel]
        for (s, d) in sorted(getattr(g, rel)):
            if s in keep and d in keep:
                out.append(f'  n{s} -> n{d} [label="{lab}", color="{col}", style={style}];')

    out.append("}")
    return "\n".join(out)


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3 and sys.argv[1] == "--case":
        import cases
        g, *_ = getattr(cases, sys.argv[2])()
        sys.stdout.write(to_dot(g, sys.argv[2]))
    elif len(sys.argv) >= 2:
        from loader import load_clou_graph
        import os
        g = load_clou_graph(sys.argv[1])
        sys.stdout.write(to_dot(g, os.path.basename(sys.argv[1]), focus=True))
    else:
        sys.stderr.write("usage: render.py <cloupy_graph.json> | --case <name>\n")
        sys.exit(2)
