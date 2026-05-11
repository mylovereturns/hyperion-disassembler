#pragma once
#include "core/loader/pe_loader.h"
#include "core/loader/elf_loader.h"
#include "core/loader/macho_loader.h"
#include "core/analysis/analyzer.h"
#include "core/analysis/bindiff.h"
#include "core/analysis/packer_detect.h"
#include "core/analysis/pdb_loader.h"
#include "core/database/database.h"
#include "core/database/export/ida_export.h"
#include "core/undo.h"
#include "threading/worker_pool.h"
#include "ui/renderer/imgui_backend.h"
#include "ui/widgets/disasm_view.h"
#include "ui/widgets/hex_view.h"
#include "ui/widgets/pseudo_view.h"
#include "ui/widgets/functions_panel.h"
#include "ui/widgets/xrefs_panel.h"
#include "ui/widgets/strings_panel.h"
#include "ui/widgets/imports_panel.h"
#include "ui/widgets/graph_view.h"
#include "ui/widgets/output_panel.h"
#include "ui/widgets/search_panel.h"
#include "ui/widgets/entropy_view.h"
#include "ui/widgets/callgraph_view.h"
#include "ui/widgets/types_panel.h"
#include "ui/widgets/diff_view.h"
#include "ui/widgets/classes_view.h"
#include "ui/widgets/stack_frame_view.h"
#include "ui/widgets/pe_header_view.h"
#include "ui/widgets/script_console.h"
#include "ui/widgets/sigmaker.h"
#include "scripting/lua_engine.h"
#include <memory>
#include <string>
#include <deque>
#include <filesystem>
#include <atomic>
#include <unordered_map>
#include <chrono>

namespace hype {

class App {
public:
    App();
    ~App();
    int run();

private:
    void open_file(const char* path);
    void render_menubar();
    void render_dockspace();
    void build_default_layout(ImGuiID dock_id);
    void handle_keys();
    void navigate_to(va_t addr);
    void nav_back();
    void nav_fwd();
    void show_goto_dlg();
    void show_rename_dlg();
    void show_rebase_dlg();
    void show_comment_dlg();
    void show_segments_dlg();
    void show_bookmarks_dlg();
    void show_sigs_dlg();
    void show_apply_type_dlg();
    void compare_with();
    void sync_panels(va_t addr);
    va_t find_func_for(va_t addr);
    void rebase(va_t new_base);
    void add_bookmark(va_t addr, const std::string& label);
    void export_patched();
    void export_asm();
    void load_recent_files();
    void save_recent_files();
    void add_recent_file(const std::string& path);
    void autosave_tick();

    Renderer         renderer_;
    WorkerPool       pool_;
    PELoader         loader_;
    ELFLoader        elf_loader_;
    MachOLoader      macho_loader_;
    Database         database_;
    IDAExport        ida_exp_;
    UndoManager      undo_;

    std::unique_ptr<PEImage>   img_;
    std::unique_ptr<Analyzer>  analyzer_;

    DisasmView       dv_;
    HexView          hv_;
    PseudoView       pv_;
    FunctionsPanel   fp_;
    XrefsPanel       xp_;
    StringsPanel     sp_;
    ImportsPanel     ip_;
    GraphView        gv_;
    OutputPanel      out_;
    SearchPanel      srch_;
    EntropyView      ev_;
    CallGraphView    cgv_;
    TypesPanel       tp_;
    DiffView         diffv_;
    StackFrameView   sfv_;
    PEHeaderView     pehv_;
    ClassesView      clsv_;
    ScriptConsole    scriptc_;
    SigMaker         sigmaker_;

    LuaEngine        lua_;
    PDBLoader        pdb_;

    std::unique_ptr<PEImage>   diff_img_;
    std::unique_ptr<Analyzer>  diff_analyzer_;
    std::vector<DiffResult>    diff_results_;

    std::deque<va_t> hist_;
    int              hist_pos_ = -1;
    bool             show_goto_ = false;
    bool             show_rename_ = false;
    bool             show_rebase_ = false;
    bool             show_comment_ = false;
    bool             show_segments_ = false;
    bool             show_bookmarks_ = false;
    bool             show_sigs_ = false;
    bool             show_apply_type_ = false;
    bool             layout_built_ = false;
    char             goto_buf_[64] = {};
    char             rename_buf_[256] = {};
    char             rebase_buf_[64] = {};
    char             comment_buf_[512] = {};
    char             bmark_buf_[128] = {};
    char             type_filter_[128] = {};
    std::string      file_path_;
    bool             busy_ = false;
    std::atomic<bool> analysis_done_{false};
    std::atomic<bool> diff_done_{false};

    struct Bookmark { va_t addr; std::string label; };
    std::vector<Bookmark> bookmarks_;

    std::deque<std::string> recent_files_;
    bool                    autosave_enabled_ = true;
    std::chrono::steady_clock::time_point last_autosave_;

    std::vector<PackerInfo> packer_results_;
};

}
