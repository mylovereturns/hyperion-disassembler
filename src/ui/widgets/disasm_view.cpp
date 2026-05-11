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

    if (beautify_) {
        // only show instructions inside functions + important data
        for (auto& [entry, func] : db_->funcs) {
            for (auto& [ba, bb] : func.blocks) {
                for (auto& insn : bb.insns)
                    addrs_.push_back(insn.addr);
            }
        }
        // include IAT entries, strings, pointers
        for (auto& [a, item] : db_->data_items) {
            if (item.style == DataStyle::Import || item.style == DataStyle::String || item.style == DataStyle::Pointer)
                addrs_.push_back(a);
        }
    } else {
        for (auto& [a, _] : db_->insns)
            addrs_.push_back(a);
        for (auto& [a, _] : db_->data_items)
            addrs_.push_back(a);
    }

    std::sort(addrs_.begin(), addrs_.end());
    addrs_.erase(std::unique(addrs_.begin(), addrs_.end()), addrs_.end());

    str_map_.clear();
    for (auto& [addr, str] : db_->strings)
        str_map_[addr] = &str;

    dirty_ = false;
}

void DisasmView::cmd_define_data() {
    if (!db_) return;
    va_t addr = cursor_;
    auto it = db_->data_items.find(addr);
    bool had_data = (it != db_->data_items.end());
    DataItem old_item = had_data ? it->second : DataItem{};
    bool had_insn = db_->insns.count(addr) > 0;
    Insn old_insn{};
    if (had_insn) old_insn = db_->insns.at(addr);

    DataSize next = DataSize::Byte;
    if (had_data) {
        switch (it->second.size) {
            case DataSize::Byte:  next = DataSize::Word;  break;
            case DataSize::Word:  next = DataSize::Dword; break;
            case DataSize::Dword: next = DataSize::Qword; break;
            case DataSize::Qword: next = DataSize::Byte;  break;
        }
    }
    db_->define_data(addr, next);
    dirty_ = true;

    if (undo_) {
        DataSize new_sz = next;
        undo_->push({
            [this, addr, had_data, old_item, had_insn, old_insn]() {
                std::lock_guard lk(db_->mtx);
                db_->data_items.erase(addr);
                if (had_data) db_->data_items[addr] = old_item;
                if (had_insn) db_->insns[addr] = old_insn;
                dirty_ = true;
            },
            [this, addr, new_sz]() { db_->define_data(addr, new_sz); dirty_ = true; },
            "define data"
        });
    }
}

void DisasmView::cmd_define_string() {
    if (!db_) return;
    va_t addr = cursor_;
    bool had_data = db_->data_items.count(addr) > 0;
    DataItem old_item = had_data ? db_->data_items.at(addr) : DataItem{};
    bool had_insn = db_->insns.count(addr) > 0;
    Insn old_insn{};
    if (had_insn) old_insn = db_->insns.at(addr);

    db_->define_string(addr);
    dirty_ = true;

    if (undo_) {
        undo_->push({
            [this, addr, had_data, old_item, had_insn, old_insn]() {
                std::lock_guard lk(db_->mtx);
                db_->data_items.erase(addr);
                if (had_data) db_->data_items[addr] = old_item;
                if (had_insn) db_->insns[addr] = old_insn;
                dirty_ = true;
            },
            [this, addr]() { db_->define_string(addr); dirty_ = true; },
            "define string"
        });
    }
}

void DisasmView::cmd_undefine() {
    if (!db_) return;
    va_t addr = cursor_;
    bool had_data = db_->data_items.count(addr) > 0;
    DataItem old_item = had_data ? db_->data_items.at(addr) : DataItem{};
    bool had_insn = db_->insns.count(addr) > 0;
    Insn old_insn{};
    if (had_insn) old_insn = db_->insns.at(addr);

    db_->undefine(addr);
    dirty_ = true;

    if (undo_) {
        undo_->push({
            [this, addr, had_data, old_item, had_insn, old_insn]() {
                std::lock_guard lk(db_->mtx);
                if (had_data) db_->data_items[addr] = old_item;
                if (had_insn) db_->insns[addr] = old_insn;
                dirty_ = true;
            },
            [this, addr]() { db_->undefine(addr); dirty_ = true; },
            "undefine"
        });
    }
}

void DisasmView::cmd_force_code() {
    if (!db_ || !img_) return;
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
    if (!db_) return;
    va_t addr = cursor_;
    db_->toggle_hex(addr);

    if (undo_) {
        undo_->push({
            [this, addr]() { db_->toggle_hex(addr); },
            [this, addr]() { db_->toggle_hex(addr); },
            "toggle hex"
        });
    }
}

void DisasmView::cmd_nop() {
    if (!db_ || !img_) return;
    va_t addr = cursor_;
    auto it = db_->insns.find(addr);
    if (it == db_->insns.end()) return;
    u8 len = it->second.len;

    std::vector<u8> old_bytes(len);
    for (auto& seg : img_->segments) {
        if (!seg.contains(addr)) continue;
        size_t off = static_cast<size_t>(addr - seg.va);
        for (u8 i = 0; i < len && off + i < seg.data.size(); ++i)
            old_bytes[i] = seg.data[off + i];
        break;
    }

    db_->patch_nop(addr, len);
    for (auto& seg : img_->segments) {
        if (!seg.contains(addr)) continue;
        size_t off = static_cast<size_t>(addr - seg.va);
        for (u8 i = 0; i < len && off + i < seg.data.size(); ++i)
            seg.data[off + i] = 0x90;
        break;
    }
    cmd_force_code();

    if (undo_) {
        undo_->push({
            [this, addr, old_bytes, len]() {
                {
                    std::lock_guard lk(db_->mtx);
                    db_->patches.erase(addr);
                }
                for (auto& seg : img_->segments) {
                    if (!seg.contains(addr)) continue;
                    size_t off = static_cast<size_t>(addr - seg.va);
                    for (u8 i = 0; i < len && off + i < seg.data.size(); ++i)
                        seg.data[off + i] = old_bytes[i];
                    break;
                }
                dirty_ = true;
            },
            [this, addr, len]() {
                db_->patch_nop(addr, len);
                for (auto& seg : img_->segments) {
                    if (!seg.contains(addr)) continue;
                    size_t off = static_cast<size_t>(addr - seg.va);
                    for (u8 i = 0; i < len && off + i < seg.data.size(); ++i)
                        seg.data[off + i] = 0x90;
                    break;
                }
                dirty_ = true;
            },
            "NOP"
        });
    }
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

    // toolbar
    if (ImGui::Checkbox("Beautify", &beautify_)) dirty_ = true;
    ImGui::SameLine();
    ImGui::TextDisabled("(%d items)", (int)addrs_.size());
    ImGui::Separator();

    float lh = ImGui::GetTextLineHeightWithSpacing();
    int total = static_cast<int>(addrs_.size());

    ImGui::BeginChild("##dasm", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    if (scroll_pending_) {
        auto it = std::lower_bound(addrs_.begin(), addrs_.end(), scroll_to_);
        if (it == addrs_.end() && !addrs_.empty())
            --it;
        if (it != addrs_.end()) {
            size_t idx = static_cast<size_t>(it - addrs_.begin());
            float target_y = idx * lh;
            float max_scroll = total * lh - ImGui::GetWindowHeight();
            float scroll = std::clamp(target_y - ImGui::GetWindowHeight() * 0.3f, 0.f, std::max(0.f, max_scroll));
            ImGui::SetScrollY(scroll);
        }
        scroll_pending_ = false;
    }

    ImGuiListClipper clip;
    clip.Begin(total, lh);

    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
            va_t a = addrs_[i];

            if (img_ && i > 0) {
                va_t prev_a = addrs_[i - 1];
                const Segment* cur_seg = nullptr;
                const Segment* prev_seg = nullptr;
                for (auto& seg : img_->segments) {
                    if (seg.contains(a)) cur_seg = &seg;
                    if (seg.contains(prev_a)) prev_seg = &seg;
                }
                if (cur_seg && cur_seg != prev_seg) {
                    ImVec2 sp = ImGui::GetCursorScreenPos();
                    float aw = ImGui::GetContentRegionAvail().x;
                    if (aw < 100) aw = 1200;
                    auto hdr = fmt::format("; === {} ===", cur_seg->name);
                    ImGui::GetWindowDrawList()->AddText(ImVec2(sp.x + 4, sp.y), col::comment(), hdr.c_str());
                    ImGui::Dummy(ImVec2(aw, lh));
                }
            }

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

    auto nit = db_->names.find(item.addr);

    switch (item.style) {
    case DataStyle::Import: {
        std::string func_name;
        if (nit != db_->names.end()) {
            auto sep = nit->second.find('!');
            func_name = (sep != std::string::npos) ? nit->second.substr(sep + 1) : nit->second;
        } else {
            func_name = fmt::format("unk_{:X}", item.addr);
        }
        const char* sz_kw = (item.size == DataSize::Qword) ? "qword" : "dword";
        auto lbl = fmt::format("extrn {}:{}", func_name, sz_kw);
        dl->AddText(ImVec2(x, y), IM_COL32(80, 210, 230, 255), lbl.c_str());
        break;
    }
    case DataStyle::String: {
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
        val += "\", 0";
        auto lbl = fmt::format("db    {}", val);
        dl->AddText(ImVec2(x, y), col::str(), lbl.c_str());
        break;
    }
    case DataStyle::Pointer: {
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
        const char* dir = (item.size == DataSize::Qword) ? "dq" : "dd";
        std::string target_name;
        auto tit = db_->names.find(static_cast<va_t>(val));
        if (tit != db_->names.end())
            target_name = tit->second;
        else
            target_name = fmt::format("sub_{:X}", val);
        auto lbl = fmt::format("{}    offset {}", dir, target_name);
        dl->AddText(ImVec2(x, y), IM_COL32(100, 160, 255, 255), lbl.c_str());
        break;
    }
    case DataStyle::Align: {
        size_t run_bytes = static_cast<size_t>(item.size);
        if (img_) {
            for (auto& seg : img_->segments) {
                if (!seg.contains(item.addr)) continue;
                size_t off = static_cast<size_t>(item.addr - seg.va);
                size_t ptr_sz = static_cast<size_t>(item.size);
                size_t j = off;
                while (j + ptr_sz <= seg.data.size()) {
                    va_t zv = 0;
                    memcpy(&zv, seg.data.data() + j, ptr_sz);
                    if (zv != 0) break;
                    j += ptr_sz;
                }
                run_bytes = j - off;
                break;
            }
        }
        auto lbl = fmt::format("align {:X}h", run_bytes);
        dl->AddText(ImVec2(x, y), IM_COL32(100, 100, 110, 255), lbl.c_str());
        break;
    }
    case DataStyle::Raw:
    default: {
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
        auto lbl = fmt::format("{}    0x{:X}", dir, val);
        dl->AddText(ImVec2(x, y), col::imm(), lbl.c_str());
        break;
    }
    }

    if (nit != db_->names.end() && item.style != DataStyle::Import) {
        float nx = pos.x + avail_w - ImGui::CalcTextSize(nit->second.c_str()).x - 16;
        if (nx > x + 200)
            dl->AddText(ImVec2(nx, y), col::comment(), fmt::format("; {}", nit->second).c_str());
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
    dl->AddText(ImVec2(x, y), mc, insn.mnemonic);
    x += 68;

    std::string annotation;
    if (insn.op_str[0]) {
        bool use_hex = db_->hex_display.count(insn.addr) == 0;
        va_t target = insn.branch_target();

        const StackFrame* frame = sfv_ ? sfv_->current_frame() : nullptr;
        std::string display_ops = frame ? format_operand_with_vars(insn, frame) : std::string(insn.op_str);

        // find reference annotation from structured operands
        for (int k = 0; k < insn.op_count && annotation.empty(); ++k) {
            va_t ref = 0;
            if (insn.ops[k].type == OpType::Imm && insn.ops[k].val > 0x10000) ref = insn.ops[k].val;
            else if (insn.ops[k].type == OpType::Mem && insn.ops[k].val) ref = insn.ops[k].val;
            if (!ref) continue;

            // exact match
            auto sit = str_map_.find(ref);
            if (sit != str_map_.end()) {
                auto& s = *sit->second;
                annotation = s.size() > 36 ? ("\"" + s.substr(0, 36) + "...\"") : ("\"" + s + "\"");
            }
            // check if ref points INTO a string (offset within first 4 bytes)
            if (annotation.empty()) {
                for (int off = 1; off <= 4 && annotation.empty(); ++off) {
                    auto sit2 = str_map_.find(ref - off);
                    if (sit2 != str_map_.end()) {
                        auto& s = *sit2->second;
                        if ((size_t)off < s.size())
                            annotation = s.size() > 36 ? ("\"" + s.substr(0, 36) + "...\"") : ("\"" + s + "\"");
                    }
                }
            }
            if (annotation.empty()) {
                auto nit = db_->names.find(ref);
                if (nit != db_->names.end() && !insn.is_call() && !insn.is_branch())
                    annotation = nit->second;
            }
        }

        // fallback: scan op_str for hex addresses matching strings/names
        if (annotation.empty()) {
            std::string ops(insn.op_str);
            size_t scan_pos = 0;
            while (scan_pos < ops.size() && annotation.empty()) {
                // find hex patterns: 0x... or raw hex sequences 7+ chars
                if (scan_pos + 2 < ops.size() && ops[scan_pos] == '0' && (ops[scan_pos+1] == 'x' || ops[scan_pos+1] == 'X')) {
                    char* end = nullptr;
                    va_t val = std::strtoull(ops.c_str() + scan_pos, &end, 16);
                    if (val > 0x10000 && end > ops.c_str() + scan_pos + 4) {
                        auto sit = str_map_.find(val);
                        if (sit != str_map_.end()) {
                            auto& s = *sit->second;
                            annotation = s.size() > 36 ? ("\"" + s.substr(0, 36) + "...\"") : ("\"" + s + "\"");
                        } else {
                            auto nit = db_->names.find(val);
                            if (nit != db_->names.end() && !insn.is_call() && !insn.is_branch())
                                annotation = nit->second;
                        }
                        scan_pos = static_cast<size_t>(end - ops.c_str());
                    } else {
                        scan_pos += 2;
                    }
                } else if (std::isxdigit((unsigned char)ops[scan_pos]) && scan_pos + 6 < ops.size()) {
                    // try parsing as raw hex (like in Intel syntax: 7FFD1234h)
                    char* end = nullptr;
                    va_t val = std::strtoull(ops.c_str() + scan_pos, &end, 16);
                    size_t len = static_cast<size_t>(end - (ops.c_str() + scan_pos));
                    if (val > 0x10000 && len >= 6) {
                        auto sit = str_map_.find(val);
                        if (sit != str_map_.end()) {
                            auto& s = *sit->second;
                            annotation = s.size() > 36 ? ("\"" + s.substr(0, 36) + "...\"") : ("\"" + s + "\"");
                        } else {
                            auto nit = db_->names.find(val);
                            if (nit != db_->names.end() && !insn.is_call() && !insn.is_branch())
                                annotation = nit->second;
                        }
                        scan_pos += len;
                    } else {
                        scan_pos++;
                    }
                } else {
                    scan_pos++;
                }
            }
        }

        if ((insn.is_call() || insn.is_branch()) && target) {
            auto nit = db_->names.find(target);
            if (nit != db_->names.end())
                dl->AddText(ImVec2(x, y), IM_COL32(120, 190, 255, 255), nit->second.c_str());
            else
                dl->AddText(ImVec2(x, y), col::imm(), display_ops.c_str());
        } else {
            if (!use_hex) {
                for (int k = 0; k < insn.op_count; ++k) {
                    if (insn.ops[k].type == OpType::Imm) {
                        auto hx = fmt::format("0x{:X}", insn.ops[k].val);
                        auto dec = fmt::format("{}", insn.ops[k].val);
                        auto p = display_ops.find(hx);
                        if (p != std::string::npos) display_ops.replace(p, hx.size(), dec);
                    }
                }
            }
            dl->AddText(ImVec2(x, y), col::reg(), display_ops.c_str());
        }
    }
    x += 220;

    auto xit = db_->xrefs_to.find(insn.addr);
    if (xit != db_->xrefs_to.end() && !xit->second.empty()) {
        auto xr_s = fmt::format("[{}x]", xit->second.size());
        dl->AddText(ImVec2(x, y), col::xref(), xr_s.c_str());
    }
    x += 44;

    // comment column: user comment > annotation > auto-comment
    auto cit = db_->comments.find(insn.addr);
    if (cit != db_->comments.end()) {
        auto ct = fmt::format("; {}", cit->second);
        dl->AddText(ImVec2(x, y), IM_COL32(90, 140, 90, 255), ct.c_str());
    } else if (!annotation.empty()) {
        auto ct = fmt::format("; {}", annotation);
        dl->AddText(ImVec2(x, y), col::str(), ct.c_str());
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
        if (ImGui::MenuItem("Generate Signature", "Ctrl+Shift+S")) {
            if (sig_cb_) sig_cb_(insn.addr);
        }
        if (ImGui::MenuItem("Copy line")) {
            auto full = fmt::format("{} {} {}", addr_s, insn.mnemonic, insn.op_str);
            ImGui::SetClipboardText(full.c_str());
        }
        if (ImGui::BeginMenu("Copy as")) {
            if (ImGui::MenuItem("C array")) {
                std::string c = "unsigned char data[] = { ";
                for (u8 b = 0; b < insn.len; ++b) {
                    if (b > 0) c += ", ";
                    c += fmt::format("0x{:02X}", insn.bytes[b]);
                }
                c += " };";
                ImGui::SetClipboardText(c.c_str());
            }
            if (ImGui::MenuItem("Python bytes")) {
                std::string py = "b'";
                for (u8 b = 0; b < insn.len; ++b)
                    py += fmt::format("\\x{:02x}", insn.bytes[b]);
                py += "'";
                ImGui::SetClipboardText(py.c_str());
            }
            if (ImGui::MenuItem("YARA hex string")) {
                std::string yara = "{ ";
                for (u8 b = 0; b < insn.len; ++b) {
                    if (b > 0) yara += " ";
                    if (b >= 2 && insn.op_count > 0 &&
                        (insn.ops[0].type == OpType::Imm || insn.ops[0].type == OpType::Mem))
                        yara += "??";
                    else
                        yara += fmt::format("{:02X}", insn.bytes[b]);
                }
                yara += " }";
                ImGui::SetClipboardText(yara.c_str());
            }
            ImGui::EndMenu();
        }
        ImGui::EndPopup();
    }

    ImGui::PopID();
}

}
