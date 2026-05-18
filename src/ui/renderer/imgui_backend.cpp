#include "imgui_backend.h"
#include "ui/fonts.h"
#include "ui/ui_utils.h"
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <spdlog/spdlog.h>
#include <filesystem>

namespace hype {

static Renderer* g_renderer = nullptr;

void glfw_drop_cb(GLFWwindow*, int count, const char** paths) {
    if (g_renderer && count > 0 && g_renderer->drop_cb_)
        g_renderer->drop_cb_(paths[0]);
}

bool Renderer::init(int w, int h, const char* title) {
    g_renderer = this;
    glfwSetErrorCallback([](int code, const char* desc) {
        spdlog::error("GLFW {}: {}", code, desc);
    });
    if (!glfwInit()) return false;

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    wnd_ = glfwCreateWindow(w, h, title, nullptr, nullptr);
    if (!wnd_) { glfwTerminate(); return false; }

    glfwMakeContextCurrent(wnd_);
    glfwSwapInterval(1);
    glfwSetDropCallback(wnd_, glfw_drop_cb);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    auto& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = "hyperion_layout.ini";

    ImFontConfig cfg;
    cfg.OversampleH = 3;
    cfg.OversampleV = 1;
    cfg.PixelSnapH = true;
    ImFontConfig mono_cfg;
    mono_cfg.OversampleH = 3;
    mono_cfg.PixelSnapH = true;
    ImFontConfig heading_cfg;
    heading_cfg.OversampleH = 3;
    heading_cfg.OversampleV = 1;
    heading_cfg.PixelSnapH = true;

    auto fonts = ui::scan_system_fonts();
    if (!fonts.empty()) {
        for (auto& f : fonts) {
            if (f.name == "Segoe UI" || f.name == "SFNS" || f.name == "DejaVu Sans" || f.name == "Ubuntu") {
                if (!g_fonts.ui) g_fonts.ui = io.Fonts->AddFontFromFileTTF(f.path.c_str(), 16.0f, &cfg);
            }
            if (f.name == "Consolas" || f.name == "SF Mono" || f.name == "DejaVu Sans Mono" || f.name == "Ubuntu Mono") {
                if (!g_fonts.mono) g_fonts.mono = io.Fonts->AddFontFromFileTTF(f.path.c_str(), 14.0f, &mono_cfg);
            }
        }
    }
    
    // Fallback if preferred fonts not found
    if (!g_fonts.ui && !fonts.empty()) g_fonts.ui = io.Fonts->AddFontFromFileTTF(fonts[0].path.c_str(), 16.0f, &cfg);
    if (!g_fonts.mono && !fonts.empty()) g_fonts.mono = io.Fonts->AddFontFromFileTTF(fonts[0].path.c_str(), 14.0f, &mono_cfg);
    
    if (!g_fonts.ui) g_fonts.ui = io.Fonts->AddFontDefault();
    if (!g_fonts.mono) g_fonts.mono = g_fonts.ui;
    if (!g_fonts.heading) g_fonts.heading = g_fonts.ui;

    ImGui_ImplGlfw_InitForOpenGL(wnd_, true);
    ImGui_ImplOpenGL3_Init("#version 330");
    return true;
}

void Renderer::shutdown() {
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    if (wnd_) glfwDestroyWindow(wnd_);
    glfwTerminate();
}

bool Renderer::begin_frame() {
    glfwPollEvents();
    int w, h;
    glfwGetFramebufferSize(wnd_, &w, &h);
    if (w == 0 || h == 0) {
        glfwWaitEvents();
        return false;
    }
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
    return true;
}

void Renderer::end_frame() {
    ImGui::Render();
    int dw, dh;
    glfwGetFramebufferSize(wnd_, &dw, &dh);
    if (dw == 0 || dh == 0) return;
    glViewport(0, 0, dw, dh);
    glClearColor(0.08f, 0.08f, 0.09f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(wnd_);
}

bool Renderer::should_close() const {
    return glfwWindowShouldClose(wnd_);
}

}
