"""Execution graph: events and the relations the type system reads.

Relations are sets of (source, destination) pairs: rf and rfx from a write to
the read it feeds, data and addr from a value to its consumer, ctrl from a
branch to a guarded event.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Set, Tuple, Optional

from lattice import Ty, PUBLIC

READ = "read"
WRITE = "write"
BRANCH = "branch"
SPECIAL = "special"


@dataclass
class Event:
    id: int
    kind: str
    transient: bool = False
    base: Ty = PUBLIC
    base_addr: Ty = PUBLIC
    name: str = ""
    is_receiver: bool = False

    def is_memory(self) -> bool:
        return self.kind in (READ, WRITE)


Rel = Set[Tuple[int, int]]


@dataclass
class Graph:
    events: Dict[int, Event] = field(default_factory=dict)
    rf: Rel = field(default_factory=set)
    rfx: Rel = field(default_factory=set)
    data: Rel = field(default_factory=set)
    addr: Rel = field(default_factory=set)
    ctrl: Rel = field(default_factory=set)
    po: Rel = field(default_factory=set)
    tfo: Rel = field(default_factory=set)

    def add_event(self, id: int, kind: str, *, transient: bool = False,
                  base: Ty = PUBLIC, base_addr: Ty = PUBLIC, name: str = "",
                  is_receiver: bool = False) -> Event:
        e = Event(id, kind, transient, base, base_addr, name, is_receiver)
        self.events[id] = e
        return e

    def add(self, rel: str, src: int, dst: int) -> None:
        getattr(self, rel).add((src, dst))

    def rf_sources(self, r: int):
        return [w for (w, rr) in self.rf if rr == r]

    def rfx_sources(self, r: int):
        return [w for (w, rr) in self.rfx if rr == r]

    def data_sources(self, y: int):
        return [x for (x, yy) in self.data if yy == y]

    def addr_sources(self, m: int):
        return [e for (e, mm) in self.addr if mm == m]

    def ctrl_branches(self, u: int):
        return [b for (b, uu) in self.ctrl if uu == u]

    def memory_events(self):
        return [e for e in self.events.values() if e.is_memory()]
