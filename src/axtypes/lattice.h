#pragma once

// Two-point lattice {L,H} and pair types <a,t> with a <= t.

#include <cassert>
#include <string>

namespace axtypes {

// false = L (public), true = H (secret)
inline bool lvl_join(bool a, bool b) { return a || b; }
inline bool lvl_leq(bool a, bool b) { return (!a) || b; }
inline const char *lvl_str(bool x) { return x ? "H" : "L"; }

struct Ty {
    bool a = false;  // architectural
    bool t = false;  // target

    Ty() = default;
    Ty(bool a_, bool t_) : a(a_), t(t_) {
        assert(lvl_leq(a, t) && "ill-formed pair type: lA must be <= lT");
    }

    Ty join(const Ty& o) const { return Ty(lvl_join(a, o.a), lvl_join(t, o.t)); }
    bool leq(const Ty& o) const { return lvl_leq(a, o.a) && lvl_leq(t, o.t); }
    bool stable() const { return a == t; }
    bool is_unstable_leak() const { return (a == false) && (t == true); }
    bool operator==(const Ty& o) const { return a == o.a && t == o.t; }
    bool operator!=(const Ty& o) const { return !(*this == o); }

    std::string str() const {
        return std::string("<") + lvl_str(a) + "," + lvl_str(t) + ">";
    }
};

inline const Ty PUBLIC{false, false};  // <L,L>
inline const Ty LEAK{false, true};  // <L,H>, unstable
inline const Ty SECRET{true, true};  // <H,H>

}
