#pragma once
#include <imgui.h>
#include <functional>
#include <string>
#include <deque>
#include "core/types.h"

#ifdef _WIN32
#include "debugger/debug_engine.h"
#include "debugger/process_list.h"
#endif

namespace hype {

#ifdef _WIN32

class DebuggerPanel {
public:
    using NavCB = std::function<void(va_t)>;
    using OpenCB = std::function<void(const std::string&)>;

    void set_nav(NavCB cb) { nav_ = std::move(cb); }
    void set_open_cb(OpenCB cb) { open_cb_ = std::move(cb); }
    void render();
    bool& visible() { return visible_; }
    DebugEngine& engine() { return engine_; }

    void show_attach_dialog() { show_attach_ = true; }
    void toggle_breakpoint(va_t addr);
    void on_step_into() { engine_.step_into(); }
    void on_step_over() { engine_.step_over(); }
    void on_step_out() { engine_.step_out(); }
    void on_run() { engine_.run(); }
    void on_pause() { engine_.pause(); }

    va_t current_rip() const { return current_rip_; }
    bool has_breakpoint(va_t addr) const;

private:
    void render_toolbar();
    void render_attach_dialog();
    void render_registers();
    void render_breakpoints();
    void render_modules();
    void render_threads();
    void render_callstack();
    void render_log();
    void poll_events();

    DebugEngine engine_;
    NavCB nav_;
    OpenCB open_cb_;
    bool visible_ = true;
    bool show_attach_ = false;

    DebugEngine::Registers regs_{};
    va_t current_rip_ = 0;

    char pid_buf_[16] = {};
    int mode_sel_ = 0;
    std::vector<ProcessEntry> proc_list_;
    int proc_sel_ = -1;
    char proc_filter_[128] = {};

    std::deque<std::string> log_lines_;
    bool log_scroll_ = true;
};

#else

class DebuggerPanel {
public:
    using NavCB = std::function<void(va_t)>;
    using OpenCB = std::function<void(const std::string&)>;

    void set_nav(NavCB) {}
    void set_open_cb(OpenCB) {}
    void render() {}
    bool& visible() { return visible_; }

    void show_attach_dialog() {}
    void toggle_breakpoint(va_t) {}
    void on_step_into() {}
    void on_step_over() {}
    void on_step_out() {}
    void on_run() {}
    void on_pause() {}

    va_t current_rip() const { return 0; }
    bool has_breakpoint(va_t) const { return false; }

private:
    bool visible_ = false;
};

#endif

}
