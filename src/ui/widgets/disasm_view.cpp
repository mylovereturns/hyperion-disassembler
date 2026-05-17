#include "disasm_view.h"
#include "stack_frame_view.h"
#ifdef _WIN32
#include "debugger/debug_engine.h"
#endif
#include "ui/theme.h"
#include "ui/fonts.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstdio>

namespace hype {

static void fmt_addr(char* buf, va_t addr) {
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 15; i >= 0; --i) { buf[i] = hex[addr & 0xF]; addr >>= 4; }
    buf[16] = '\0';
}

static void fmt_hex_bytes(char* buf, const u8* bytes, int len, int max_bytes = 4) {
    static const char hex[] = "0123456789ABCDEF";
    int nb = len < max_bytes ? len : max_bytes;
    nb = nb < 6 ? nb : 6;
    char* p = buf;
    for (int b = 0; b < nb; ++b) {
        *p++ = hex[bytes[b] >> 4];
        *p++ = hex[bytes[b] & 0xF];
        *p++ = ' ';
    }
    if (len > 6) { *p++ = '.'; *p++ = '.'; }
    *p = '\0';
}

void DisasmView::goto_addr(va_t addr) {
    scroll_to_ = addr;
    scroll_pending_ = true;
    cursor_ = addr;
    if (live_mode_)
        live_base_ = addr;
}

void DisasmView::rebuild() {
    if (!db_) return;
    addrs_.clear();
    addrs_.reserve(db_->insns.size() + db_->data_items.size());

    if (beautify_) {
        for (auto& [entry, func] : db_->funcs) {
            for (auto& [ba, bb] : func.blocks) {
                db_->for_each_insn_in_block(bb, [&](const Insn& insn) {
                    addrs_.push_back(insn.addr);
                });
            }
        }
        for (auto& [a, item] : db_->data_items) {
            if (item.style == DataStyle::Import || item.style == DataStyle::String || item.style == DataStyle::Pointer)
                addrs_.push_back(a);
        }
    } else {
        for (auto& insn : db_->insns)
            addrs_.push_back(insn.addr);
        for (auto& [a, _] : db_->data_items)
            addrs_.push_back(a);
    }

    std::sort(addrs_.begin(), addrs_.end());
    addrs_.erase(std::unique(addrs_.begin(), addrs_.end()), addrs_.end());

    str_map_.clear();
    for (auto& [addr, str] : db_->strings)
        str_map_[addr] = &str;

    rebuild_data_cache();
    rebuild_insn_cache();

    seg_hdr_cache_.clear();
    if (img_) {
        for (auto& seg : img_->segments)
            seg_hdr_cache_[seg.va] = fmt::format("; === {} ===", seg.name);
    }

    dirty_ = false;
}

void DisasmView::rebuild_data_cache() {
    data_cache_.clear();
    data_cache_.reserve(db_->data_items.size());

    for (auto& [a, item] : db_->data_items) {
        CachedDataLine c;
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
            c.label = fmt::format("extrn {}:{}", func_name, sz_kw);
            c.color = IM_COL32(80, 210, 230, 255);
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
            c.label = fmt::format("db    {}", val);
            c.color = col::str();
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
            c.label = fmt::format("{}    offset {}", dir, target_name);
            c.color = IM_COL32(100, 160, 255, 255);
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
            c.label = fmt::format("align {:X}h", run_bytes);
            c.color = IM_COL32(100, 100, 110, 255);
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
            c.label = fmt::format("{}    0x{:X}", dir, val);
            c.color = col::imm();
            break;
        }
        }

        if (nit != db_->names.end() && item.style != DataStyle::Import)
            c.name_comment = fmt::format("; {}", nit->second);

        data_cache_[a] = std::move(c);
    }
}

void DisasmView::rebuild_insn_cache() {
    insn_cache_.clear();
    insn_cache_.reserve(db_->insns.size());

    for (auto& insn : db_->insns) {
        CachedInsnLine c;
        fmt_hex_bytes(c.hex, insn.bytes, insn.len);

        // pre-build annotation
        std::string annotation;
        for (int k = 0; k < insn.op_count && annotation.empty(); ++k) {
            va_t ref = 0;
            if (insn.ops[k].type == OpType::Imm && insn.ops[k].val > 0x10000) ref = insn.ops[k].val;
            else if (insn.ops[k].type == OpType::Mem && insn.ops[k].val) ref = insn.ops[k].val;
            if (!ref) continue;

            auto sit = str_map_.find(ref);
            if (sit != str_map_.end()) {
                auto& s = *sit->second;
                annotation = s.size() > 36 ? ("\"" + s.substr(0, 36) + "...\"") : ("\"" + s + "\"");
            }
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

        if (annotation.empty()) {
            std::string ops(insn.op_str);
            size_t scan_pos = 0;
            while (scan_pos < ops.size() && annotation.empty()) {
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

        c.annotation = std::move(annotation);
        insn_cache_[insn.addr] = std::move(c);
    }
}

void DisasmView::cmd_define_data() {
    if (!db_) return;
    va_t addr = cursor_;
    auto it = db_->data_items.find(addr);
    bool had_data = (it != db_->data_items.end());
    DataItem old_item = had_data ? it->second : DataItem{};
    bool had_insn = db_->insns.count(addr) > 0;
    Insn old_insn{};
    if (had_insn) { auto iit = db_->insns.find(addr); old_insn = *iit; }

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
    if (had_insn) { auto iit = db_->insns.find(addr); old_insn = *iit; }

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
    if (had_insn) { auto iit = db_->insns.find(addr); old_insn = *iit; }

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
    u8 len = it->len;

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
        if (img_->arch == Arch::ARM64) {
            for (u8 i = 0; i + 3 < len && off + i + 3 < seg.data.size(); i += 4) {
                seg.data[off + i]     = 0x1F;
                seg.data[off + i + 1] = 0x20;
                seg.data[off + i + 2] = 0x03;
                seg.data[off + i + 3] = 0xD5;
            }
        } else {
            for (u8 i = 0; i < len && off + i < seg.data.size(); ++i)
                seg.data[off + i] = 0x90;
        }
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
        db_->for_each_insn_in_block(bb, [&](const Insn& insn) {
            for (int k = 0; k < insn.op_count; ++k) {
                auto& op = insn.ops[k];
                if (op.type == OpType::Reg && op.reg == highlighted_reg_) {
                    reg_highlight_addrs_.insert(insn.addr);
                    break;
                }
                if (op.type == OpType::Mem &&
                    (op.mem_base == highlighted_reg_ || op.mem_index == highlighted_reg_)) {
                    reg_highlight_addrs_.insert(insn.addr);
                    break;
                }
            }
        });
    }
}

void DisasmView::render() {
    ImGui::Begin("Disassembly");
    if (!db_ || !img_) { ImGui::TextDisabled("No binary loaded"); ImGui::End(); return; }

#ifdef _WIN32
    if (dbg_eng_ && dbg_eng_->is_attached() && !dbg_eng_->is_running()) {
        if (!live_mode_ || scroll_pending_) {
            va_t center = scroll_pending_ ? scroll_to_ : (live_base_ ? live_base_ : debug_rip_);
            va_t read_start = center > 0x200 ? center - 0x200 : 0;
            u8 buf[0x1000];
            if (dbg_eng_->read_memory(read_start, buf, sizeof(buf))) {
                Disassembler dis;
                dis.set_arch(Arch::X64);
                live_insns_ = dis.decode_range(read_start, buf, sizeof(buf));
                live_base_ = read_start;
            }
            live_mode_ = true;
            scroll_pending_ = false;
        }

        if (g_fonts.mono) ImGui::PushFont(g_fonts.mono);
        float lh = ImGui::GetTextLineHeightWithSpacing();
        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.4f, 1.0f), "LIVE");
        ImGui::SameLine();
        ImGui::TextDisabled("(%d insns @ %016llX)", (int)live_insns_.size(), (unsigned long long)live_base_);
        ImGui::Separator();
        render_live(lh);
        if (g_fonts.mono) ImGui::PopFont();
        ImGui::End();
        return;
    }
#endif

    live_mode_ = false;

    if (dirty_) rebuild();
    if (addrs_.empty()) { ImGui::TextDisabled("No instructions"); ImGui::End(); return; }

    // toolbar
    if (ImGui::Checkbox("Beautify", &beautify_)) dirty_ = true;
    ImGui::SameLine();
    ImGui::TextDisabled("(%d items)", (int)addrs_.size());
    ImGui::Separator();

    if (g_fonts.mono) ImGui::PushFont(g_fonts.mono);
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
                    auto hit = seg_hdr_cache_.find(cur_seg->va);
                    if (hit != seg_hdr_cache_.end())
                        ImGui::GetWindowDrawList()->AddText(ImVec2(sp.x + 4, sp.y), col::comment(), hit->second.c_str());
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
                render_line(i, *it, lh);
        }
    }

    ImGui::EndChild();
    if (g_fonts.mono) ImGui::PopFont();
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

    char addr_buf[17];
    fmt_addr(addr_buf, item.addr);
    dl->AddText(ImVec2(x, y), is_cursor ? IM_COL32(130, 190, 255, 255) : col::addr(), addr_buf);
    x += ImGui::CalcTextSize("0000000000000000").x + 14;

    auto cit = data_cache_.find(item.addr);
    if (cit != data_cache_.end()) {
        dl->AddText(ImVec2(x, y), cit->second.color, cit->second.label.c_str());
        if (!cit->second.name_comment.empty()) {
            float nx = pos.x + avail_w - ImGui::CalcTextSize(cit->second.name_comment.c_str()).x - 16;
            if (nx > x + 200)
                dl->AddText(ImVec2(nx, y), col::comment(), cit->second.name_comment.c_str());
        }
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
        float tw = ImGui::CalcTextSize(fn.name.c_str()).x + ImGui::CalcTextSize("  ").x;
        float cx = hpos.x + (avail_w - tw) * 0.5f;
        dl->AddText(ImVec2(cx, hpos.y + 1), col::func(), fn.name.c_str());
        ImGui::Dummy(ImVec2(avail_w, lh));
    }

    ImGui::PushID(static_cast<int>(insn.addr & 0x7FFFFFFF) ^ (idx << 16));

    ImVec2 pos = ImGui::GetCursorScreenPos();

    if (is_cursor)
        dl->AddRectFilled(pos, ImVec2(pos.x + avail_w, pos.y + lh), IM_COL32(40, 55, 85, 255));
    else if (reg_hl)
        dl->AddRectFilled(pos, ImVec2(pos.x + avail_w, pos.y + lh), IM_COL32(35, 45, 55, 180));

    // debug: RIP indicator (yellow)
    if (debug_rip_ && insn.addr == debug_rip_)
        dl->AddRectFilled(pos, ImVec2(pos.x + avail_w, pos.y + lh), IM_COL32(80, 80, 20, 200));

    // debug: breakpoint indicator (red dot)
    if (debug_bps_) {
        for (va_t bp : *debug_bps_) {
            if (bp == insn.addr) {
                dl->AddCircleFilled(ImVec2(pos.x + 6, pos.y + lh * 0.5f), 4.0f, IM_COL32(220, 50, 50, 255));
                break;
            }
        }
    }

    float x = pos.x + 4;
    float y = pos.y;

    char addr_buf[17];
    fmt_addr(addr_buf, insn.addr);
    dl->AddText(ImVec2(x, y), is_cursor ? IM_COL32(130, 190, 255, 255) : col::addr(), addr_buf);
    x += ImGui::CalcTextSize("0000000000000000").x + 14;

    auto cache_it = insn_cache_.find(insn.addr);
    const char* hex_str = cache_it != insn_cache_.end() ? cache_it->second.hex : "";
    dl->AddText(ImVec2(x, y), IM_COL32(85, 85, 95, 255), hex_str);
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

    const std::string* annotation_ptr = nullptr;
    if (cache_it != insn_cache_.end() && !cache_it->second.annotation.empty())
        annotation_ptr = &cache_it->second.annotation;

    if (insn.op_str[0]) {
        bool use_hex = db_->hex_display.count(insn.addr) == 0;
        va_t target = insn.branch_target();

        const StackFrame* frame = sfv_ ? sfv_->current_frame() : nullptr;
        std::string display_ops_buf;
        const char* display_ops;
        if (frame) {
            display_ops_buf = format_operand_with_vars(insn, frame);
            display_ops = display_ops_buf.c_str();
        } else {
            display_ops = insn.op_str;
        }

        if ((insn.is_call() || insn.is_branch()) && target) {
            auto nit = db_->names.find(target);
            if (nit != db_->names.end())
                dl->AddText(ImVec2(x, y), IM_COL32(120, 190, 255, 255), nit->second.c_str());
            else
                dl->AddText(ImVec2(x, y), col::imm(), display_ops);
        } else {
            if (!use_hex) {
                if (display_ops_buf.empty()) display_ops_buf = insn.op_str;
                for (int k = 0; k < insn.op_count; ++k) {
                    if (insn.ops[k].type == OpType::Imm) {
                        auto hx = fmt::format("0x{:X}", insn.ops[k].val);
                        auto dec = fmt::format("{}", insn.ops[k].val);
                        auto p = display_ops_buf.find(hx);
                        if (p != std::string::npos) display_ops_buf.replace(p, hx.size(), dec);
                    }
                }
                dl->AddText(ImVec2(x, y), col::reg(), display_ops_buf.c_str());
            } else {
                dl->AddText(ImVec2(x, y), col::reg(), display_ops);
            }
        }
    }
    x += 220;

    auto xit = db_->xrefs_to.find(insn.addr);
    if (xit != db_->xrefs_to.end() && !xit->second.empty()) {
        char xr_buf[16];
        snprintf(xr_buf, sizeof(xr_buf), "[%dx]", (int)xit->second.size());
        dl->AddText(ImVec2(x, y), col::xref(), xr_buf);
    }
    x += 44;

    auto comment_it = db_->comments.find(insn.addr);
    if (comment_it != db_->comments.end()) {
        char ct_buf[256];
        snprintf(ct_buf, sizeof(ct_buf), "; %s", comment_it->second.c_str());
        dl->AddText(ImVec2(x, y), IM_COL32(90, 140, 90, 255), ct_buf);
    } else if (annotation_ptr) {
        char ct_buf[256];
        snprintf(ct_buf, sizeof(ct_buf), "; %s", annotation_ptr->c_str());
        dl->AddText(ImVec2(x, y), col::str(), ct_buf);
    } else if ((insn.is_call() || insn.is_branch()) && insn.branch_target()) {
        auto nit = db_->names.find(insn.branch_target());
        if (nit != db_->names.end()) {
            char ct_buf[256];
            snprintf(ct_buf, sizeof(ct_buf), "; %s", nit->second.c_str());
            dl->AddText(ImVec2(x, y), IM_COL32(65, 85, 65, 255), ct_buf);
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
            if (insn.ops[k].type == OpType::Mem && insn.ops[k].mem_base) {
                highlighted_reg_ = insn.ops[k].mem_base;
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
            ImGui::SetClipboardText(addr_buf);
        }
        if (ImGui::MenuItem("Generate Signature", "Ctrl+Shift+S")) {
            if (sig_cb_) sig_cb_(insn.addr);
        }
        if (ImGui::MenuItem("Copy line")) {
            auto full = fmt::format("{} {} {}", addr_buf, insn.mnemonic, insn.op_str);
            ImGui::SetClipboardText(full.c_str());
        }
        if (ImGui::BeginMenu("Copy as")) {
            if (ImGui::MenuItem("C array")) {
                std::string c = "unsigned char data[] = { ";
                u8 copy_len = std::min<u8>(insn.len, sizeof(insn.bytes));
                for (u8 b = 0; b < copy_len; ++b) {
                    if (b > 0) c += ", ";
                    c += fmt::format("0x{:02X}", insn.bytes[b]);
                }
                c += " };";
                ImGui::SetClipboardText(c.c_str());
            }
            if (ImGui::MenuItem("Python bytes")) {
                std::string py = "b'";
                u8 copy_len = std::min<u8>(insn.len, sizeof(insn.bytes));
                for (u8 b = 0; b < copy_len; ++b)
                    py += fmt::format("\\x{:02x}", insn.bytes[b]);
                py += "'";
                ImGui::SetClipboardText(py.c_str());
            }
            if (ImGui::MenuItem("YARA hex string")) {
                std::string yara = "{ ";
                u8 copy_len = std::min<u8>(insn.len, sizeof(insn.bytes));
                for (u8 b = 0; b < copy_len; ++b) {
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

#ifdef _WIN32
void DisasmView::render_live(float lh) {
    ImGui::BeginChild("##dasm_live", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    int total = static_cast<int>(live_insns_.size());
    if (total == 0) {
        ImGui::TextDisabled("No instructions decoded");
        ImGui::EndChild();
        return;
    }

    // scroll to RIP
    if (debug_rip_) {
        for (int i = 0; i < total; ++i) {
            if (live_insns_[i].addr == debug_rip_) {
                float target_y = i * lh;
                float max_scroll = total * lh - ImGui::GetWindowHeight();
                float scroll = std::clamp(target_y - ImGui::GetWindowHeight() * 0.3f, 0.f, std::max(0.f, max_scroll));
                ImGui::SetScrollY(scroll);
                break;
            }
        }
    }

    ImGuiListClipper clip;
    clip.Begin(total, lh);
    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i)
            render_live_line(i, live_insns_[i], lh);
    }

    // navigation: scroll near edges reads more memory
    float sy = ImGui::GetScrollY();
    float max_sy = ImGui::GetScrollMaxY();
    if (max_sy > 0) {
        if (sy <= 0 && live_base_ > 0x200) {
            va_t new_base = live_base_ - 0x800;
            u8 buf[0x1000];
            if (dbg_eng_->read_memory(new_base, buf, sizeof(buf))) {
                Disassembler dis;
                dis.set_arch(Arch::X64);
                live_insns_ = dis.decode_range(new_base, buf, sizeof(buf));
                live_base_ = new_base;
            }
        } else if (sy >= max_sy) {
            va_t new_base = live_base_ + 0x800;
            u8 buf[0x1000];
            if (dbg_eng_->read_memory(new_base, buf, sizeof(buf))) {
                Disassembler dis;
                dis.set_arch(Arch::X64);
                live_insns_ = dis.decode_range(new_base, buf, sizeof(buf));
                live_base_ = new_base;
            }
        }
    }

    ImGui::EndChild();
}

void DisasmView::render_live_line(int idx, const Insn& insn, float lh) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float avail_w = ImGui::GetContentRegionAvail().x;
    if (avail_w < 100) avail_w = 1200;
    bool is_cursor = (insn.addr == cursor_);
    bool is_rip = (debug_rip_ && insn.addr == debug_rip_);

    ImGui::PushID(static_cast<int>(insn.addr & 0x7FFFFFFF) ^ (idx << 16));
    ImVec2 pos = ImGui::GetCursorScreenPos();

    if (is_rip)
        dl->AddRectFilled(pos, ImVec2(pos.x + avail_w, pos.y + lh), IM_COL32(80, 80, 20, 200));
    else if (is_cursor)
        dl->AddRectFilled(pos, ImVec2(pos.x + avail_w, pos.y + lh), IM_COL32(40, 55, 85, 255));

    if (debug_bps_) {
        for (va_t bp : *debug_bps_) {
            if (bp == insn.addr) {
                dl->AddCircleFilled(ImVec2(pos.x + 6, pos.y + lh * 0.5f), 4.0f, IM_COL32(220, 50, 50, 255));
                break;
            }
        }
    }

    float x = pos.x + 16;
    float y = pos.y;

    if (is_rip) {
        dl->AddText(ImVec2(pos.x + 2, y), IM_COL32(255, 220, 50, 255), ">");
    }

    auto addr_s = fmt::format("{:016X}", insn.addr);
    dl->AddText(ImVec2(x, y), is_cursor ? IM_COL32(130, 190, 255, 255) : col::addr(), addr_s.c_str());
    x += ImGui::CalcTextSize("0000000000000000").x + 14;

    std::string hex;
    int nb = std::min<int>(insn.len, (int)sizeof(insn.bytes));
    nb = std::min(nb, 6);
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

    if (insn.op_str[0])
        dl->AddText(ImVec2(x, y), col::reg(), insn.op_str);

    ImGui::InvisibleButton("##ll", ImVec2(avail_w, lh));

    if (ImGui::IsItemHovered() && !is_cursor)
        dl->AddRectFilled(pos, ImVec2(pos.x + avail_w, pos.y + lh), IM_COL32(30, 40, 60, 140));

    if (ImGui::IsItemClicked(ImGuiMouseButton_Left))
        cursor_ = insn.addr;

    if (ImGui::IsItemClicked(ImGuiMouseButton_Left) && ImGui::GetIO().KeyShift) {
        if (dbg_eng_)
            dbg_eng_->set_breakpoint(insn.addr);
    }

    ImGui::PopID();
}
#endif

}
