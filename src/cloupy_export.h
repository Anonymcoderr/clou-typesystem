#pragma once

#include "aeg/aeg.h"
#include "util/z3.h"
#include <string>
#include <vector>

namespace cloupy {

// Write one execution of the AEG as JSON (cloupy-graph-v1).
void export_graph_to_json(
    const aeg::AEG& aeg,
    const z3::eval& eval,
    const std::string& output_path,
    const NodeRefSet& exec_window = NodeRefSet()
);

void export_all_executions(
    const aeg::AEG& aeg,
    const std::vector<std::pair<z3::eval, NodeRefSet>>& executions,
    const std::string& base_output_dir
);

}
