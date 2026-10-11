#pragma once

// Execution graph: events and the relations the type system reads.

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "lattice.h"

namespace axtypes {

enum class Kind { Read, Write, Branch, Special, Other };

struct Event {
    int id = 0;
    Kind kind = Kind::Other;
    bool transient = false;
    Ty base = PUBLIC;  // seed for the value
    Ty base_addr = PUBLIC;  // seed for the address
    std::string name;
    bool is_receiver = false;
    bool attacker = false;  // attacker-controlled value

    bool is_memory() const { return kind == Kind::Read || kind == Kind::Write; }
};

using Rel = std::set<std::pair<int, int>>;

struct Graph {
    std::map<int, Event> events;
    Rel rf, rfx, data, addr, ctrl, po, tfo;

    Event& add_event(int id, Kind kind, bool transient = false,
                     Ty base = PUBLIC, Ty base_addr = PUBLIC,
                     const std::string& name = "", bool is_receiver = false,
                     bool attacker = false) {
        Event e;
        e.id = id; e.kind = kind; e.transient = transient;
        e.base = base; e.base_addr = base_addr; e.name = name;
        e.is_receiver = is_receiver; e.attacker = attacker;
        events[id] = e;
        return events[id];
    }

    void add(Rel& rel, int src, int dst) { rel.insert({src, dst}); }

    std::vector<int> preds(const Rel& rel, int dst) const {
        std::vector<int> out;
        for (const auto& [s, d] : rel)
            if (d == dst) out.push_back(s);
        return out;
    }

    std::vector<const Event *> memory_events() const {
        std::vector<const Event *> out;
        for (const auto& [id, e] : events)
            if (e.is_memory()) out.push_back(&e);
        return out;
    }
};

}
