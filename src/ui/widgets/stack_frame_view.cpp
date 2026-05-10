#include "stack_frame_view.h"
#include "ui/theme.h"
#include <fmt/format.h>
#include <Zydis/Zydis.h>

namespace hype {

void StackFrame::analyze(const Function& func) {
    func_entry = func.entry;
    vars.clear();
    frame_size = 0;

    for (auto& [ba, bb] : func.blocks) {
        for (auto& insn : bb.insns) {
            for (u8 k = 0; k < insn.op_count; ++k) {
                auto& op = insn.ops[k];
                if (op.type != OpType::Mem) continue;

                bool is_rsp = op.mem.base == ZYDIS_REGISTER_RSP || op.mem.base == ZYDIS_REGISTER_ESP;
                bool is_rbp = op.mem.base == ZYDIS_REGISTER_RBP || op.mem.base == ZYDIS_REGISTER_EBP;
                if (!is_rsp && !is_rbp) continue;

                i64 disp = op.mem.disp;
                if (vars.count(disp)) continue;

                u16 sz = op.size ? op.size / 8 : 8;
                if (sz == 0) sz = 8;

                std::string name;
                if (is_rbp) {
                    if (disp >= 0)
                        name = fmt::format("arg_{:X}", disp);
                    else
                        name = fmt::format("var_{:X}", -disp);
                } else {
                    if (disp >= 0x28)
                        name = fmt::format("arg_{:X}", disp);
                    else
                        name = fmt::format("var_{:X}", disp);
                }

                vars[disp] = {disp, name, sz, 0};
            }
        }
    }

    i64 min_off = 0;
    i64 max_off = 0;
    for (auto& [off, _] : vars) {
        if (off < min_off) min_off = off;
        if (off > max_off) max_off = off;
    }
    frame_size = max_off - min_off + 8;
}

void StackFrame::rename(i64 offset, std::string new_name) {
    auto it = vars.find(offset);
    if (it != vars.end())
        it->second.name = std::move(new_name);
}

const StackVar* StackFrame::find(i64 offset) const {
    auto it = vars.find(offset);
    return it != vars.end() ? &it->second : nullptr;
}

void StackFrameView::set_function(va_t entry) {
    if (func_ == entry) return;
    func_ = entry;
    if (!entry || !db_) return;

    if (!frames_.count(entry)) {
        auto fit = db_->funcs.find(entry);
        if (fit != db_->funcs.end()) {
            StackFrame sf;
            sf.analyze(fit->second);
            frames_[entry] = std::move(sf);
        }
    }
}

const StackFrame* StackFrameView::current_frame() const {
    auto it = frames_.find(func_);
    return it != frames_.end() ? &it->second : nullptr;
}

void StackFrameView::render() {
    ImGui::Begin("Stack Frame");

    if (!db_ || !func_) {
        ImGui::TextDisabled("No function selected");
        ImGui::End();
        return;
    }

    auto fit = db_->funcs.find(func_);
    if (fit == db_->funcs.end()) {
        ImGui::TextDisabled("Function not found");
        ImGui::End();
        return;
    }

    auto* frame = const_cast<StackFrame*>(current_frame());
    if (!frame) { ImGui::End(); return; }

    ImGui::Text("%s  (frame size: %lld bytes)", fit->second.name.c_str(), (long long)frame->frame_size);
    ImGui::Separator();

    if (ImGui::BeginTable("##sframe", 4,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableHeadersRow();

        for (auto& [off, var] : frame->vars) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (off >= 0)
                ImGui::Text("+0x%llX", (unsigned long long)off);
            else
                ImGui::Text("-0x%llX", (unsigned long long)(-off));

            ImGui::TableNextColumn();
            ImGui::PushID((int)(off & 0x7FFFFFFF));
            if (ImGui::Selectable(var.name.c_str(), false)) {
                renaming_ = true;
                rename_offset_ = off;
                rename_buf_[0] = 0;
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            ImGui::Text("%d", var.size);

            ImGui::TableNextColumn();
            if (var.type_id && db_) {
                auto* td = db_->types.get(var.type_id);
                if (td) ImGui::TextUnformatted(td->name.c_str());
                else ImGui::TextDisabled("???");
            } else {
                ImGui::TextDisabled("-");
            }
        }
        ImGui::EndTable();
    }

    if (renaming_) {
        if (!ImGui::IsPopupOpen("Rename Var")) ImGui::OpenPopup("Rename Var");
        if (ImGui::BeginPopupModal("Rename Var", &renaming_, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text("Offset: %+lld", (long long)rename_offset_);
            if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
            bool go = ImGui::InputText("Name##rv", rename_buf_, sizeof(rename_buf_),
                ImGuiInputTextFlags_EnterReturnsTrue);
            if (go || ImGui::Button("OK##rv")) {
                if (rename_buf_[0])
                    frame->rename(rename_offset_, rename_buf_);
                renaming_ = false;
                rename_buf_[0] = 0;
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel##rv")) { renaming_ = false; ImGui::CloseCurrentPopup(); }
            ImGui::EndPopup();
        }
    }

    ImGui::End();
}

std::string format_operand_with_vars(const Insn& insn, const StackFrame* frame) {
    if (!frame || !insn.op_str[0]) return std::string(insn.op_str);

    std::string result = insn.op_str;

    for (u8 k = 0; k < insn.op_count; ++k) {
        auto& op = insn.ops[k];
        if (op.type != OpType::Mem) continue;

        bool is_rsp = op.mem.base == ZYDIS_REGISTER_RSP || op.mem.base == ZYDIS_REGISTER_ESP;
        bool is_rbp = op.mem.base == ZYDIS_REGISTER_RBP || op.mem.base == ZYDIS_REGISTER_EBP;
        if (!is_rsp && !is_rbp) continue;

        i64 disp = op.mem.disp;
        auto* var = frame->find(disp);
        if (!var) continue;

        const char* base_name = is_rsp ? (op.mem.base == ZYDIS_REGISTER_ESP ? "esp" : "rsp")
                                       : (op.mem.base == ZYDIS_REGISTER_EBP ? "ebp" : "rbp");

        if (disp > 0) {
            auto hex_pat = fmt::format("[{}+0x{:X}]", base_name, disp);
            auto hex_pat2 = fmt::format("[{}+{:X}h]", base_name, disp);
            auto replacement = fmt::format("[{}+{}]", base_name, var->name);

            auto pos = result.find(hex_pat);
            if (pos != std::string::npos) {
                result.replace(pos, hex_pat.size(), replacement);
                continue;
            }
            pos = result.find(hex_pat2);
            if (pos != std::string::npos) {
                result.replace(pos, hex_pat2.size(), replacement);
                continue;
            }

            auto hex_pat3 = fmt::format("[{}+{:02X}h]", base_name, disp);
            pos = result.find(hex_pat3);
            if (pos != std::string::npos) {
                result.replace(pos, hex_pat3.size(), replacement);
                continue;
            }
        } else if (disp < 0) {
            u64 abs_disp = static_cast<u64>(-disp);
            auto hex_pat = fmt::format("[{}-0x{:X}]", base_name, abs_disp);
            auto hex_pat2 = fmt::format("[{}-{:X}h]", base_name, abs_disp);
            auto replacement = fmt::format("[{}-{}]", base_name, var->name);

            auto pos = result.find(hex_pat);
            if (pos != std::string::npos) {
                result.replace(pos, hex_pat.size(), replacement);
                continue;
            }
            pos = result.find(hex_pat2);
            if (pos != std::string::npos) {
                result.replace(pos, hex_pat2.size(), replacement);
                continue;
            }
        }
    }

    return result;
}

}
