"""Two-point lattice {L,H} and pair types <a,t> with a <= t."""
from __future__ import annotations
from dataclasses import dataclass

# False = L (public), True = H (secret)
L = False
H = True


def lvl_join(a: bool, b: bool) -> bool:
    return a or b


def lvl_leq(a: bool, b: bool) -> bool:
    return (not a) or b


def lvl_str(x: bool) -> str:
    return "H" if x else "L"


@dataclass(frozen=True)
class Ty:
    """Pair type <a,t> with a <= t."""
    a: bool
    t: bool

    def __post_init__(self):
        if not lvl_leq(self.a, self.t):
            raise ValueError(f"ill-formed pair type <{lvl_str(self.a)},{lvl_str(self.t)}>: "
                             "architectural component must be <= target component")

    def join(self, other: "Ty") -> "Ty":
        return Ty(lvl_join(self.a, other.a), lvl_join(self.t, other.t))

    def leq(self, other: "Ty") -> bool:
        return lvl_leq(self.a, other.a) and lvl_leq(self.t, other.t)

    def stable(self) -> bool:
        """Both components agree: <L,L> or <H,H>.  <L,H> is unstable."""
        return self.a == self.t

    def is_unstable_leak(self) -> bool:
        """Exactly <L,H>: architecturally public but target-secret."""
        return (self.a == L) and (self.t == H)

    def __str__(self) -> str:
        return f"<{lvl_str(self.a)},{lvl_str(self.t)}>"


PUBLIC = Ty(L, L)
LEAK = Ty(L, H)
SECRET = Ty(H, H)

BOT = PUBLIC


def join_all(tys) -> Ty:
    """Join a (possibly empty) iterable of Ty; empty join = <L,L>."""
    acc = BOT
    for ty in tys:
        acc = acc.join(ty)
    return acc
