#pragma once

// Seeds for Clou's threat model: a transient read at a data-dependent address
// may return a secret, so its value is seeded <L,H>.

#include <string>

#include "graph.h"

namespace axtypes {

inline Kind kind_from_cloupy(const std::string& s) {
    if (s == "read") return Kind::Read;
    if (s == "write") return Kind::Write;
    if (s == "branch") return Kind::Branch;
    if (s == "special" || s == "receiver") return Kind::Special;
    return Kind::Other;
}

// Every transient read that has an address predecessor.
inline void apply_clou_secret_policy(Graph& g) {
    std::set<int> has_incoming_addr;
    for (const auto& [s, d] : g.addr) has_incoming_addr.insert(d);
    for (auto& [id, e] : g.events) {
        if (e.kind == Kind::Read && e.transient && has_incoming_addr.count(id))
            e.base = LEAK;
        else
            e.base = PUBLIC;
    }
}

// Only when some address predecessor is attacker-controlled.
inline void apply_clou_secret_policy_gated(Graph& g) {
    std::map<int, std::vector<int>> addr_preds;
    for (const auto& [s, d] : g.addr) addr_preds[d].push_back(s);
    for (auto& [id, e] : g.events) {
        bool seed = false;
        if (e.kind == Kind::Read && e.transient) {
            auto it = addr_preds.find(id);
            if (it != addr_preds.end()) {
                for (int p : it->second) {
                    auto pe = g.events.find(p);
                    if (pe != g.events.end() && pe->second.attacker) { seed = true; break; }
                }
            }
        }
        e.base = seed ? LEAK : PUBLIC;
    }
}

}
