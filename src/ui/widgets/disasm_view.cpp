#include "disasm_view.h"
#include "stack_frame_view.h"
#include "ui/theme.h"
#include <fmt/format.h>
#include <algorithm>

namespace hype {

void DisasmView::goto_addr(va_t addr) {
    scroll_to_ = addr;
    scroll_pending_ = true;
    cursor_ = addr;
}

void DisasmView::rebuild() {
    if (!db_) return;
    addrs_.clear();
    addrs_.reserve(db_->insns.size() + db_->data_items.size());
    for (auto& [a, _] : db_->insns)
        addrs_.push_back(a);
    for (auto& [a, _] : db_->data_items)
        addrs_.push_back(a);
    std::sort(addrs_.begin(), addrs_.end());
    addrs_.erase(std::unique(addrs_.begin(), addrs_.end()), addrs_.end());
    dirty_ = false;
}

void DisasmView::cmd_define_data() {
    if (!db_ || !cursor_) return;
    auto it = db_->data_items.find(cursor_);
    DataSize next = DataSize::Byte;
    if (it != db_->data_items.end()) {
        switch (it->second.size) {
            case DataSize::Byte:  next = DataSize::Word;  break;
            case DataSize::Word:  next = DataSize::Dword; break;
            case DataSize::Dword: next = DataSize::Qword; break;
            case DataSize::Qword: next = DataSize::Byte;  break;
        }
    }
    db_->define_data(cursor_, next);
    dirty_ = true;
}

void DisasmView::cmd_define_string() {
    if (!db_ || !cursor_) return;
    db_->define_string(cursor_);
    dirty_ = true;
}

void DisasmView::cmd_undefine() {
    if (!db_ || !cursor_) return;
    db_->undefine(cursor_);
    dirty_ = true;
}

void DisasmView::cmd_force_code() {
    if (!db_ || !img_ || !cursor_) return;
    for (auto& seg : img_->segments) {
        if (!seg.contains(cursor_)) continue;
        size_t off = static_cast<size_t>(cursor_ - seg.va);
        if (off >= seg.data.size()) return;
        Disassembler dis;
        dis.set_arch(img_->arch);
        Insn insn{};
        if (dis.decode(cursor_, seg.data.data() + off, seg.data.size() - off, insn)) {
            std::lock_guard lk(db_->mtx);
            db_->data_items.erase(cursor_);
            db_->insns[cursor_] = std::move(insn);
            dirty_ = true;
        }
        return;
    }
}

void DisasmView::cmd_toggle_hex() {
    if (!db_ || !cursor_) return;
    db_->toggle_hex(cursor_);
}

void DisasmView::cmd_nop() {
    if (!db_ || !cursor_) return;
    auto it = db_->insns.find(cursor_);
    if (it == db_->insns.end()) return;
    u8 len = it->second.len;
    db_->patch_nop(cursor_, len);
    for (auto& seg : img_->segments) {
        if (!seg.contains(cursor_)) continue;
        size_t off = static_cast<size_t>(cursor_ - seg.va);
        for (u8 i = 0; i < len && off + i < seg.data.size(); ++i)
            seg.data[off + i] = 0x90;
        break;
    }
    cmd_force_code();
}

void DisasmView::update_reg_highlight() {
    reg_highlight_addrs_.clear();
    if (!highlighted_reg_ || !db_) return;

    va_t func_entry = 0;
    for (auto& [entry, func] : db_->funcs) {
        for (auto& [ba, bb] : func.blocks) {
            if (cursor_ >= bb.start && cursor_ < bb.end) {
                func_entry = entry;
                goto found;
            }
        }
    }
    found:
    if (!func_entry) return;

    auto& func = db_->funcs.at(func_entry);
    for (auto& [ba, bb] : func.blocks) {
        for (auto& insn : bb.insns) {
            for (int k = 0; k < insn.op_count; ++k) {
                auto& op = insn.ops[k];
                if (op.type == OpType::Reg && op.reg == highlighted_reg_) {
                    reg_highlight_addrs_.insert(insn.addr);
                    break;
                }
                if (op.type == OpType::Mem &&
                    (op.mem.base == highlighted_reg_ || op.mem.index == highlighted_reg_)) {
                    reg_highlight_addrs_.insert(insn.addr);
                    break;
                }
            }
        }
    }
}

void DisasmView::render() {
    ImGui::Begin("Disassembly");
    if (!db_ || !img_) { ImGui::TextDisabled("No binary loaded"); ImGui::End(); return; }
    if (dirty_) rebuild();
    if (addrs_.empty()) { ImGui::TextDisabled("No instructions"); ImGui::End(); return; }

    float lh = ImGui::GetTextLineHeightWithSpacing();
    int total = static_cast<int>(addrs_.size());

    ImGui::BeginChild("##dasm", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    if (scroll_pending_) {
        auto it = std::lower_bound(addrs_.begin(), addrs_.end(), scroll_to_);
        if (it != addrs_.end()) {
            float target_y = static_cast<float>(it - addrs_.begin()) * lh;
            float view_h = ImGui::GetContentRegionAvail().y;
            ImGui::SetScrollY(std::max(0.f, target_y - view_h * 0.3f));
        } else if (!addrs_.empty()) {
            // address not found - scroll to nearest
            it = std::lower_bound(addrs_.begin(), addrs_.end(), scroll_to_);
            if (it != addrs_.begin()) --it;
            float target_y = static_cast<float>(it - addrs_.begin()) * lh;
            ImGui::SetScrollY(std::max(0.f, target_y - ImGui::GetContentRegionAvail().y * 0.3f));
        }
        scroll_pending_ = false;
    }

    ImGuiListClipper clip;
    clip.Begin(total, lh);

    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
            va_t a = addrs_[i];
            auto dit = db_->data_items.find(a);
            if (dit != db_->data_items.end()) {
                render_data_line(dit->second, lh);
                continue;
            }
            auto it = db_->insns.find(a);
            if (it != db_->insns.end())
                render_line(i, it->second, lh);
        }
    }

    ImGui::EndChild();
    ImGui::End();
}

void DisasmView::render_data_line(const DataItem& item, float lh) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float avail_w = ImGui::GetContentRegionAvail().x;
    if (avail_w < 100) avail_w = 1200;
    bool is_cursor = (item.addr == cursor_);

    ImGui::PushID(static_cast<int>(item.addr & 0x7FFFFFFF));
    ImVec2 pos = ImGui::GetCursorScreenPos();

    if (is_cursor)
        dl->AddRectFilled(pos, ImVec2(pos.x + avail_w, pos.y + lh), IM_COL32(40, 55, 85, 255));

    float x = pos.x + 4;
    float y = pos.y;

    auto addr_s = fmt::format("{:016X}", item.addr);
    dl->AddText(ImVec2(x, y), is_cursor ? IM_COL32(130, 190, 255, 255) : col::addr(), addr_s.c_str());
    x += ImGui::CalcTextSize("0000000000000000").x + 14;

    if (item.is_string) {
        std::string val = "\"";
        if (img_) {
            for (auto& seg : img_->segments) {
                if (!seg.contains(item.addr)) continue;
                size_t off = static_cast<size_t>(item.addr - seg.va);
                for (size_t i = off; i < seg.data.size() && seg.data[i]; ++i)
                    val += static_cast<char>(seg.data[i]);
                break;
            }
        }
        val += "\"";
        auto lbl = fmt::format("db  {}", val);
        dl->AddText(ImVec2(x, y), col::str(), lbl.c_str());
    } else {
        const char* dir = "db";
        switch (item.size) {
            case DataSize::Word:  dir = "dw"; break;
            case DataSize::Dword: dir = "dd"; break;
            case DataSize::Qword: dir = "dq"; break;
            default: break;
        }
        u64 val = 0;
        if (img_) {
            for (auto& seg : img_->segments) {
                if (!seg.contains(item.addr)) continue;
                size_t off = static_cast<size_t>(item.addr - seg.va);
                size_t sz = static_cast<size_t>(item.size);
                if (off + sz <= seg.data.size())
                    memcpy(&val, seg.data.data() + off, sz);
                break;
            }
        }
        auto lbl = fmt::format("{}  0x{:X}", dir, val);
        dl->AddText(ImVec2(x, y), col::imm(), lbl.c_str());
    }

    ImGui::InvisibleButton("##dl", ImVec2(avail_w, lh));
    if (ImGui::IsItemClicked(ImGuiMouseButton_Left))
        cursor_ = item.addr;
    ImGui::PopID();
}

void DisasmView::render_line(int idx, const Insn& insn, float lh) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float avail_w = ImGui::GetContentRegionAvail().x;
    if (avail_w < 100) avail_w = 1200;
    bool is_cursor = (insn.addr == cursor_);
    bool reg_hl = reg_highlight_addrs_.count(insn.addr) > 0;

    if (db_->funcs.count(insn.addr)) {
        auto& fn = db_->funcs.at(insn.addr);
        ImVec2 hpos = ImGui::GetCursorScreenPos();
        dl->AddRectFilled(hpos, ImVec2(hpos.x + avail_w, hpos.y + lh), IM_COL32(20, 24, 32, 255));
        dl->AddLine(ImVec2(hpos.x, hpos.y), ImVec2(hpos.x + avail_w, hpos.y), IM_COL32(60, 70, 90, 255));
        auto header = fmt::format(" {} ", fn.name);
        float tw = ImGui::CalcTextSize(header.c_str()).x;
        float cx = hpos.x + (avail_w - tw) * 0.5f;
        dl->AddText(ImVec2(cx, hpos.y + 1), col::func(), header.c_str());
        ImGui::Dummy(ImVec2(avail_w, lh));
    }

    ImGui::PushID(static_cast<int>(insn.addr & 0x7FFFFFFF) ^ (idx << 16));

    ImVec2 pos = ImGui::GetCursorScreenPos();

    if (is_cursor)
        dl->AddRectFilled(pos, ImVec2(pos.x + avail_w, pos.y + lh), IM_COL32(40, 55, 85, 255));
    else if (reg_hl)
        dl->AddRectFilled(pos, ImVec2(pos.x + avail_w, pos.y + lh), IM_COL32(35, 45, 55, 180));

    float x = pos.x + 4;
    float y = pos.y;

    auto addr_s = fmt::format("{:016X}", insn.addr);
    dl->AddText(ImVec2(x, y), is_cursor ? IM_COL32(130, 190, 255, 255) : col::addr(), addr_s.c_str());
    x += ImGui::CalcTextSize("0000000000000000").x + 14;

    std::string hex;
    int nb = std::min<int>(insn.len, 6);
    for (int b = 0; b < nb; ++b) hex += fmt::format("{:02X} ", insn.bytes[b]);
    if (insn.len > 6) hex += "..";
    dl->AddText(ImVec2(x, y), IM_COL32(85, 85, 95, 255), hex.c_str());
    x += ImGui::CalcTextSize("00 00 00 00 00 00 ..").x + 10;

    ImU32 mc = col::mnem();
    switch (insn.type) {
        case InsnType::Call:    mc = IM_COL32(255, 200, 80, 255); break;
        case InsnType::Jmp:    mc = IM_COL32(80, 220, 80, 255); break;
        case InsnType::Jcc:    mc = IM_COL32(80, 200, 130, 255); break;
        case InsnType::Ret:    mc = IM_COL32(230, 90, 90, 255); break;
        case InsnType::Nop:    mc = IM_COL32(70, 70, 70, 255); break;
        case InsnType::Push:
        case InsnType::Pop:    mc = IM_COL32(150, 150, 195, 255); break;
        case InsnType::Int:
        case InsnType::Syscall: mc = IM_COL32(210, 90, 210, 255); break;
        default: break;
    }
    dl->AddText(ImVec2(x, y), mc, insn.mnemonic.c_str());
    x += 68;

    if (!insn.op_str.empty()) {
        bool use_hex = db_->hex_display.count(insn.addr) == 0;
        va_t target = insn.branch_target();
        if ((insn.is_call() || insn.is_branch()) && target) {
            auto nit = db_->names.find(target);
            if (nit != db_->names.end())
                dl->AddText(ImVec2(x, y), IM_COL32(120, 190, 255, 255), nit->second.c_str());
            else
                dl->AddText(ImVec2(x, y), col::imm(), insn.op_str.c_str());
        } else {
            const StackFrame* frame = sfv_ ? sfv_->current_frame() : nullptr;
            std::string ops = frame ? format_operand_with_vars(insn, frame) : insn.op_str;
            if (!use_hex) {
                for (int k = 0; k < insn.op_count; ++k) {
                    if (insn.ops[k].type == OpType::Imm) {
                        auto hx = fmt::format("0x{:X}", insn.ops[k].val);
                        auto dec = fmt::format("{}", insn.ops[k].val);
                        auto p = ops.find(hx);
                        if (p != std::string::npos) ops.replace(p, hx.size(), dec);
                    }
                }
            }
            dl->AddText(ImVec2(x, y), col::reg(), ops.c_str());
        }
    }
    x += 220;

    auto xit = db_->xrefs_to.find(insn.addr);
    if (xit != db_->xrefs_to.end() && !xit->second.empty()) {
        auto xr_s = fmt::format("[{}x]", xit->second.size());
        dl->AddText(ImVec2(x, y), col::xref(), xr_s.c_str());
    }
    x += 44;

    auto cit = db_->comments.find(insn.addr);
    if (cit != db_->comments.end()) {
        auto ct = fmt::format("; {}", cit->second);
        dl->AddText(ImVec2(x, y), IM_COL32(90, 140, 90, 255), ct.c_str());
    } else if ((insn.is_call() || insn.is_branch()) && insn.branch_target()) {
        auto nit = db_->names.find(insn.branch_target());
        if (nit != db_->names.end()) {
            auto ct = fmt::format("; {}", nit->second);
            dl->AddText(ImVec2(x, y), IM_COL32(65, 85, 65, 255), ct.c_str());
        }
    }

    ImGui::InvisibleButton("##ln", ImVec2(avail_w, lh));

    if (ImGui::IsItemHovered() && !is_cursor)
        dl->AddRectFilled(pos, ImVec2(pos.x + avail_w, pos.y + lh), IM_COL32(30, 40, 60, 140));

    if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
        cursor_ = insn.addr;
        highlighted_reg_ = 0;
        for (int k = 0; k < insn.op_count; ++k) {
            if (insn.ops[k].type == OpType::Reg && insn.ops[k].reg) {
                highlighted_reg_ = insn.ops[k].reg;
                break;
            }
            if (insn.ops[k].type == OpType::Mem && insn.ops[k].mem.base) {
                highlighted_reg_ = insn.ops[k].mem.base;
                break;
            }
        }
        update_reg_highlight();
    }

    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
        va_t t = insn.branch_target();
        if (t && db_->insns.count(t)) {
            cursor_ = t;
            goto_addr(t);
            if (nav_) nav_(t);
        }
    }

    if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
        cursor_ = insn.addr;

    if (ImGui::BeginPopupContextItem()) {
        va_t t = insn.branch_target();
        if (t && ImGui::MenuItem("Follow target (Enter)")) {
            cursor_ = t; goto_addr(t); if (nav_) nav_(t);
        }
        if (ImGui::MenuItem("Xrefs to here (X)")) {}
        if (ImGui::MenuItem("Xrefs from here")) {}
        ImGui::Separator();
        if (ImGui::MenuItem("Rename (N)")) {}
        if (ImGui::MenuItem("Comment (;)")) {}
        if (ImGui::MenuItem("Bookmark (Ctrl+B)")) {}
        ImGui::Separator();
        if (ImGui::MenuItem("Define data (D)")) cmd_define_data();
        if (ImGui::MenuItem("Define string (A)")) cmd_define_string();
        if (ImGui::MenuItem("Undefine (U)")) cmd_undefine();
        if (ImGui::MenuItem("Force code (C)")) cmd_force_code();
        if (ImGui::MenuItem("NOP out")) cmd_nop();
        ImGui::Separator();
        if (ImGui::MenuItem("Copy address")) {
            ImGui::SetClipboardText(addr_s.c_str());
        }
        if (ImGui::MenuItem("Copy line")) {
            auto full = fmt::format("{} {} {}", addr_s, insn.mnemonic, insn.op_str);
            ImGui::SetClipboardText(full.c_str());
        }
        ImGui::EndPopup();
    }

    ImGui::PopID();
}

}
