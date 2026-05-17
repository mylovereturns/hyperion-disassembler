#include "debugger_panel.h"

#ifdef _WIN32

#include "ui/theme.h"
#include <fmt/format.h>
#include <algorithm>

namespace hype {

void DebuggerPanel::render() {
    if (!visible_) return;

    poll_events();

    ImGui::Begin("Debugger", &visible_, ImGuiWindowFlags_None);
    render_toolbar();

    if (ImGui::BeginTabBar("##dbg_tabs")) {
        if (ImGui::BeginTabItem("Registers")) { render_registers(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Breakpoints")) { render_breakpoints(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Modules")) { render_modules(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Threads")) { render_threads(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Call Stack")) { render_callstack(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Log")) { render_log(); ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }
    ImGui::End();

    render_attach_dialog();
}

void DebuggerPanel::render_toolbar() {
    bool attached = engine_.is_attached();
    bool running = engine_.is_running();

    if (!attached) {
        if (ImGui::Button("Attach...")) show_attach_ = true;
    } else {
        if (running) {
            if (ImGui::Button("Pause")) engine_.pause();
        } else {
            if (ImGui::Button("Run (F9)")) engine_.run();
            ImGui::SameLine();
            if (ImGui::Button("Step Into (F7)")) engine_.step_into();
            ImGui::SameLine();
            if (ImGui::Button("Step Over (F8)")) engine_.step_over();
            ImGui::SameLine();
            if (ImGui::Button("Step Out")) engine_.step_out();
        }
        ImGui::SameLine();
        if (ImGui::Button("Detach")) engine_.detach();

        ImGui::SameLine();
        ImGui::TextDisabled("PID: %u | %s", engine_.pid(),
            running ? "Running" : "Paused");
    }
    ImGui::Separator();
}

void DebuggerPanel::render_attach_dialog() {
    if (!show_attach_) return;

    ImGui::OpenPopup("Attach to Process");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(500, 400), ImGuiCond_Appearing);

    if (ImGui::BeginPopupModal("Attach to Process", &show_attach_)) {
        ImGui::Text("Mode:");
        ImGui::SameLine();
        ImGui::RadioButton("Normal", &mode_sel_, 0);
        ImGui::SameLine();
        ImGui::RadioButton("Stealth", &mode_sel_, 1);

        ImGui::Separator();
        ImGui::InputTextWithHint("##pid", "PID", pid_buf_, sizeof(pid_buf_));
        ImGui::SameLine();
        if (ImGui::Button("Attach##byPid")) {
            u32 pid = (u32)atoi(pid_buf_);
            if (pid > 0) {
                auto mode = mode_sel_ == 1 ? DebugMode::Stealth : DebugMode::Normal;
                engine_.set_log_cb([this](const std::string& msg) {
                    log_lines_.push_back(msg);
                    if (log_lines_.size() > 1000) log_lines_.pop_front();
                });
                if (engine_.attach(pid, mode)) {
                    show_attach_ = false;
                    // auto-open the binary
                    if (open_cb_) {
                        char path[MAX_PATH] = {};
                        HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                        if (hp) {
                            DWORD sz = MAX_PATH;
                            QueryFullProcessImageNameA(hp, 0, path, &sz);
                            CloseHandle(hp);
                        }
                        if (path[0]) open_cb_(path);
                    }
                }
            }
        }

        ImGui::Separator();
        ImGui::InputTextWithHint("##pfilter", "Filter processes...", proc_filter_, sizeof(proc_filter_));
        ImGui::SameLine();
        if (ImGui::Button("Refresh")) {
            proc_list_ = enumerate_processes();
        }

        if (proc_list_.empty() && ImGui::IsWindowAppearing())
            proc_list_ = enumerate_processes();

        if (ImGui::BeginChild("##proclist", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()))) {
            if (ImGui::BeginTable("##proctbl", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders)) {
                ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 60);
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                std::string filter_lower(proc_filter_);
                std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(), ::tolower);

                for (int i = 0; i < (int)proc_list_.size(); i++) {
                    auto& p = proc_list_[i];
                    if (!filter_lower.empty()) {
                        std::string name_lower = p.name;
                        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
                        if (name_lower.find(filter_lower) == std::string::npos) continue;
                    }

                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    bool sel = (proc_sel_ == i);
                    if (ImGui::Selectable(fmt::format("{}", p.pid).c_str(), sel, ImGuiSelectableFlags_SpanAllColumns)) {
                        proc_sel_ = i;
                        snprintf(pid_buf_, sizeof(pid_buf_), "%u", p.pid);
                    }
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(p.name.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(p.path.c_str());
                }
                ImGui::EndTable();
            }
        }
        ImGui::EndChild();

        ImGui::EndPopup();
    }
}

void DebuggerPanel::render_registers() {
    if (!engine_.is_attached() || engine_.is_running()) {
        ImGui::TextDisabled("Not paused");
        return;
    }

    regs_ = engine_.get_registers();
    current_rip_ = regs_.rip;

    auto reg_row = [](const char* name, u64 val) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(name);
        ImGui::TableNextColumn();
        ImGui::Text("%016llX", (unsigned long long)val);
    };

    if (ImGui::BeginTable("##regs", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
        ImGui::TableSetupColumn("Reg", ImGuiTableColumnFlags_WidthFixed, 40);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        reg_row("RAX", regs_.rax); reg_row("RBX", regs_.rbx);
        reg_row("RCX", regs_.rcx); reg_row("RDX", regs_.rdx);
        reg_row("RSI", regs_.rsi); reg_row("RDI", regs_.rdi);
        reg_row("RBP", regs_.rbp); reg_row("RSP", regs_.rsp);
        reg_row("RIP", regs_.rip);
        reg_row("R8", regs_.r8); reg_row("R9", regs_.r9);
        reg_row("R10", regs_.r10); reg_row("R11", regs_.r11);
        reg_row("R12", regs_.r12); reg_row("R13", regs_.r13);
        reg_row("R14", regs_.r14); reg_row("R15", regs_.r15);

        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextUnformatted("EFLAGS");
        ImGui::TableNextColumn();
        ImGui::Text("%08X [%s%s%s%s%s]", regs_.eflags,
            (regs_.eflags & 0x0001) ? "CF " : "",
            (regs_.eflags & 0x0040) ? "ZF " : "",
            (regs_.eflags & 0x0080) ? "SF " : "",
            (regs_.eflags & 0x0800) ? "OF " : "",
            (regs_.eflags & 0x0004) ? "PF " : "");

        ImGui::EndTable();
    }

    if (ImGui::Button("Go to RIP") && nav_)
        nav_(regs_.rip);
}

void DebuggerPanel::render_breakpoints() {
    auto& bps = engine_.breakpoints();
    if (bps.empty()) { ImGui::TextDisabled("No breakpoints"); return; }

    if (ImGui::BeginTable("##bps", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
        ImGui::TableSetupColumn("Addr", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("Enabled", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("##del", ImGuiTableColumnFlags_WidthFixed, 30);
        ImGui::TableHeadersRow();

        va_t to_remove = INVALID_VA;
        for (auto& bp : bps) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (ImGui::Selectable(fmt::format("{:016X}", bp.addr).c_str(), false) && nav_)
                nav_(bp.addr);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(bp.is_hardware ? "HW" : "SW");
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(bp.enabled ? "Yes" : "No");
            ImGui::TableNextColumn();
            if (ImGui::SmallButton(fmt::format("X##{}", bp.addr).c_str()))
                to_remove = bp.addr;
        }
        ImGui::EndTable();

        if (to_remove != INVALID_VA)
            engine_.remove_breakpoint(to_remove);
    }
}

void DebuggerPanel::render_modules() {
    auto& mods = engine_.modules();
    if (mods.empty()) { ImGui::TextDisabled("No modules"); return; }

    if (ImGui::BeginTable("##mods", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (auto& m : mods) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (ImGui::Selectable(fmt::format("{:016X}", m.base).c_str(), false) && nav_)
                nav_(m.base);
            ImGui::TableNextColumn();
            ImGui::Text("%08X", m.size);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(m.name.c_str());
        }
        ImGui::EndTable();
    }
}

void DebuggerPanel::render_threads() {
    auto& threads = engine_.threads();
    if (threads.empty()) { ImGui::TextDisabled("No threads"); return; }

    if (ImGui::BeginTable("##thr", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
        ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Handle", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("TEB", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (auto& t : threads) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%u", t.id);
            ImGui::TableNextColumn(); ImGui::Text("%p", t.handle);
            ImGui::TableNextColumn(); ImGui::Text("%016llX", (unsigned long long)t.teb);
        }
        ImGui::EndTable();
    }
}

void DebuggerPanel::render_callstack() {
    if (!engine_.is_attached() || engine_.is_running()) {
        ImGui::TextDisabled("Not paused");
        return;
    }

    // Walk RBP chain
    struct Frame { va_t ret_addr; va_t rbp; };
    std::vector<Frame> frames;

    va_t rbp = regs_.rbp;
    va_t rip = regs_.rip;
    frames.push_back({rip, rbp});

    for (int i = 0; i < 64 && rbp != 0; i++) {
        va_t next_rbp = 0, ret = 0;
        if (!engine_.read_memory(rbp, &next_rbp, 8)) break;
        if (!engine_.read_memory(rbp + 8, &ret, 8)) break;
        if (ret == 0) break;
        frames.push_back({ret, next_rbp});
        rbp = next_rbp;
    }

    if (ImGui::BeginTable("##stack", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 30);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (int i = 0; i < (int)frames.size(); i++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%d", i);
            ImGui::TableNextColumn();
            if (ImGui::Selectable(fmt::format("{:016X}", frames[i].ret_addr).c_str(), false) && nav_)
                nav_(frames[i].ret_addr);
        }
        ImGui::EndTable();
    }
}

void DebuggerPanel::render_log() {
    if (ImGui::Button("Clear")) log_lines_.clear();
    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll", &log_scroll_);

    ImGui::BeginChild("##dbglog", ImVec2(0, 0), true);
    for (auto& line : log_lines_)
        ImGui::TextUnformatted(line.c_str());
    if (log_scroll_ && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
}

void DebuggerPanel::poll_events() {
    if (!engine_.is_attached()) return;

    for (int i = 0; i < 16; i++) {
        auto ev = engine_.poll_event();
        if (ev.type == DebugEngine::DebugEvent::None) break;

        if (!ev.detail.empty())
            log_lines_.push_back(ev.detail);

        switch (ev.type) {
        case DebugEngine::DebugEvent::Breakpoint_Hit:
        case DebugEngine::DebugEvent::SingleStep:
            regs_ = engine_.get_registers();
            current_rip_ = regs_.rip;
            if (nav_) nav_(current_rip_);
            break;
        case DebugEngine::DebugEvent::ProcessExit:
            log_lines_.push_back("Process terminated");
            break;
        default:
            break;
        }

        if (log_lines_.size() > 1000) log_lines_.pop_front();
    }
}

void DebuggerPanel::toggle_breakpoint(va_t addr) {
    if (!engine_.is_attached()) return;
    if (has_breakpoint(addr))
        engine_.remove_breakpoint(addr);
    else
        engine_.set_breakpoint(addr);
}

bool DebuggerPanel::has_breakpoint(va_t addr) const {
    for (auto& bp : engine_.breakpoints())
        if (bp.addr == addr && bp.enabled) return true;
    return false;
}

}

#endif
