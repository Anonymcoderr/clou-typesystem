#include "cloupy_export.h"
#include "aeg/aeg.h"
#include "cfg/expanded.h"
#include "util/output.h"
#include "config.h"
#include <fstream>
#include <sstream>
#include <iomanip>

namespace cloupy {

std::string to_json_string(const std:: string& s) {
    std::ostringstream oss;
    oss << std::quoted(s);
    return oss.str();
}

std::string event_kind_to_string(const aeg::Node& node) {
    const auto* inst = node.inst->get_inst();
    if (!inst) {
        if (node.inst->kind() == Inst::Kind::ENTRY) return "special";
        if (node.inst->kind() == Inst::Kind::EXIT) return "receiver";
        return "other";
    }

    if (llvm::isa<llvm::LoadInst>(inst)) {
        return "read";
    }
    if (llvm::isa<llvm::StoreInst>(inst)) {
        return "write";
    }
    if (llvm::isa<llvm::BranchInst>(inst)) {
        return "branch";
    }
    return "other";
}

std:: string exec_mode_to_string(const aeg::Node& node, const z3::eval& eval) {
    if (eval(node.arch)) {
        return "arch";
    }
    if (eval(node.trans)) {
        return "spec";
    }
    return "arch";
}

std::string edge_kind_to_string(aeg::Edge::Kind kind) {
    switch (kind) {
        case aeg::Edge::RF: return "rf";
        case aeg::Edge::RFX: return "rfx";
        case aeg::Edge::DATA:  return "data";
        case aeg::Edge::ADDR: return "addr";
        case aeg::Edge::ADDR_GEP: return "addr";
        case aeg::Edge:: CTRL: return "ctrl";
        case aeg::Edge::PO: return "po";
        case aeg::Edge::TFO: return "tfo";
        default: return "other";
    }
}

void export_graph_to_json(
    const aeg::AEG& aeg,
    const z3::eval& eval,
    const std::string& output_path,
    const NodeRefSet& exec_window
) {
    std::ofstream ofs(output_path);
    if (!ofs) {
        llvm::errs() << "Error: Cannot open file for writing:  " << output_path << "\n";
        return;
    }

    ofs << "{\n";
    ofs << "  \"version\": \"cloupy-graph-v1\",\n";

    ofs << "  \"events\":  [\n";
    bool first_event = true;

    for (NodeRef ref : aeg.po. reverse_postorder()) {
        if (! exec_window.empty() && exec_window.find(ref) == exec_window.end()) {
            continue;
        }

        const aeg::Node& node = aeg.lookup(ref);

        if (! first_event) {
            ofs << ",\n";
        }
        first_event = false;

        ofs << "    {\n";
        ofs << "      \"id\": " << static_cast<int>(ref) << ",\n";

        std::string name = util::to_string(*node.inst);
        ofs << "      \"name\": " << to_json_string(name) << ",\n";

        ofs << "      \"kind\": " << to_json_string(event_kind_to_string(node)) << ",\n";

        std::string base = node.attacker_taint ? "H" : "L";
        ofs << "      \"base\":  " << to_json_string(base) << ",\n";

        bool struct_unsafe = false;
        if (const llvm:: Instruction* I = node.inst->get_inst()) {
            if (eval(node.trans) && (llvm::isa<llvm::LoadInst>(I) || llvm::isa<llvm::StoreInst>(I))) {
                struct_unsafe = true;
            }
        }
        ofs << "      \"struct_unsafe\": " << (struct_unsafe ? "true" :  "false") << ",\n";

        bool is_receiver = (node.inst->kind() == Inst::Kind::EXIT);
        ofs << "      \"is_receiver\": " << (is_receiver ? "true" : "false") << ",\n";

        ofs << "      \"exec_mode\": " << to_json_string(exec_mode_to_string(node, eval)) << ",\n";

        ofs << "      \"guard\": null\n";

        ofs << "    }";
    }

    ofs << "\n  ],\n";

    ofs << "  \"edges\": [\n";
    bool first_edge = true;

    aeg.graph.for_each_edge([&](NodeRef src, NodeRef dst, const aeg::Edge& edge) {
        if (!exec_window.empty()) {
            if (exec_window.find(src) == exec_window.end() ||
                exec_window.find(dst) == exec_window.end()) {
                return;
            }
        }

        if (! eval(edge.exists)) {
            return;
        }

        std::string kind_str = edge_kind_to_string(edge.kind);

        if (kind_str == "other") {
            return;
        }

        if (!first_edge) {
            ofs << ",\n";
        }
        first_edge = false;

        ofs << "    {\n";
        ofs << "      \"kind\": " << to_json_string(kind_str) << ",\n";
        ofs << "      \"src\": " << static_cast<int>(src) << ",\n";
        ofs << "      \"dst\": " << static_cast<int>(dst) << "\n";
        ofs << "    }";
    });

    ofs << "\n  ]\n";
    ofs << "}\n";

    ofs.close();
    llvm::errs() << "ClouPy graph exported to: " << output_path << "\n";
}

void export_all_executions(
    const aeg::AEG& aeg,
    const std::vector<std::pair<z3::eval, NodeRefSet>>& executions,
    const std::string& base_output_dir
) {
    unsigned idx = 0;
    for (const auto& [eval, exec_window] : executions) {
        std::stringstream ss;
        ss << base_output_dir << "/execution_" << idx << ".json";
        export_graph_to_json(aeg, eval, ss. str(), exec_window);
        ++idx;
    }
}

}
