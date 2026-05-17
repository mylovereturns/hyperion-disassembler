#include "callgraph_view.h"
#include <fmt/format.h>
#include <algorithm>

namespace hype {

void CallGraphView::show_function(va_t entry) {
    if (target_ == entry) return;
    target_ = entry;
    callers_.clear();
    callees_.clear();
    if (!db_ || !entry) return;

    auto xit = db_->xrefs_to.find(entry);
    if (xit != db_->xrefs_to.end()) {
        for (auto& xr : xit->second) {
            if (xr.type != XrefType::CodeCall) continue;
            std::string n = fmt::format("sub_{:X}", xr.from);
            auto nit = db_->names.find(xr.from);
            if (nit != db_->names.end()) n = nit->second;
            else {
                for (auto& [fe, fn] : db_->funcs) {
                    for (auto& [ba, bb] : fn.blocks) {
                        if (xr.from >= bb.start && xr.from < bb.end) {
                            auto fnit = db_->names.find(fe);
                            n = fnit != db_->names.end() ? fnit->second : fmt::format("sub_{:X}", fe);
                            goto found_caller;
                        }
                    }
                }
                found_caller:;
            }
            callers_.push_back({xr.from, n});
        }
    }

    auto xfit = db_->xrefs_from.find(entry);
    if (xfit != db_->xrefs_from.end()) {
        for (auto& xr : xfit->second) {
            if (xr.type != XrefType::CodeCall) continue;
            std::string n = fmt::format("sub_{:X}", xr.to);
            auto nit = db_->names.find(xr.to);
            if (nit != db_->names.end()) n = nit->second;
            callees_.push_back({xr.to, n});
        }
    }

    if (db_->funcs.count(entry)) {
        auto& func = db_->funcs.at(entry);
        for (auto& [ba, bb] : func.blocks) {
            db_->for_each_insn_in_block(bb, [&](const Insn& insn) {
                if (!insn.is_call()) return;
                va_t t = insn.branch_target();
                if (!t) return;
                bool dup = false;
                for (auto& e : callees_)
                    if (e.addr == t) { dup = true; break; }
                if (dup) return;
                std::string n = fmt::format("sub_{:X}", t);
                auto nit = db_->names.find(t);
                if (nit != db_->names.end()) n = nit->second;
                callees_.push_back({t, n});
            });
        }
    }
}

void CallGraphView::render() {
    ImGui::Begin("Call Graph");
    if (!db_ || !target_) { ImGui::TextDisabled("Select a function"); ImGui::End(); return; }

    std::string tname = fmt::format("sub_{:X}", target_);
    auto nit = db_->names.find(target_);
    if (nit != db_->names.end()) tname = nit->second;

    float w = ImGui::GetContentRegionAvail().x;
    float col_w = w / 3.0f - 8;

    ImGui::BeginChild("##callers", ImVec2(col_w, 0), true);
    ImGui::TextColored(ImVec4(0.6f, 0.8f, 1.0f, 1.0f), "Callers (%zu)", callers_.size());
    ImGui::Separator();
    for (int i = 0; i < (int)callers_.size(); ++i) {
        auto lbl = fmt::format("{}##{}", callers_[i].name, i);
        if (ImGui::Selectable(lbl.c_str()))
            if (nav_) nav_(callers_[i].addr);
    }
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginChild("##target", ImVec2(col_w, 0), true);
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "Selected");
    ImGui::Separator();
    auto tlbl = fmt::format("{:016X}\n{}", target_, tname);
    ImGui::TextWrapped("%s", tlbl.c_str());
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginChild("##callees", ImVec2(col_w, 0), true);
    ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.6f, 1.0f), "Callees (%zu)", callees_.size());
    ImGui::Separator();
    for (int i = 0; i < (int)callees_.size(); ++i) {
        auto lbl = fmt::format("{}##c{}", callees_[i].name, i);
        if (ImGui::Selectable(lbl.c_str()))
            if (nav_) nav_(callees_[i].addr);
    }
    ImGui::EndChild();

    ImGui::End();
}

}
