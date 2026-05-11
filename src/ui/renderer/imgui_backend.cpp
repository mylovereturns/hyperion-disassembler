#include "imgui_backend.h"
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <spdlog/spdlog.h>

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

#ifdef _WIN32
    io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 16.0f, &cfg);
    io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\consola.ttf", 14.0f, &mono_cfg);
#elif defined(__APPLE__)
    if (!io.Fonts->AddFontFromFileTTF("/System/Library/Fonts/SFNSMono.ttf", 15.0f, &cfg))
        if (!io.Fonts->AddFontFromFileTTF("/System/Library/Fonts/Menlo.ttc", 15.0f, &cfg))
            io.Fonts->AddFontDefault(&cfg);
    if (!io.Fonts->AddFontFromFileTTF("/System/Library/Fonts/SFNSMono.ttf", 14.0f, &mono_cfg))
        if (!io.Fonts->AddFontFromFileTTF("/System/Library/Fonts/Menlo.ttc", 14.0f, &mono_cfg))
            io.Fonts->AddFontDefault(&mono_cfg);
#else
    if (!io.Fonts->AddFontFromFileTTF("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 15.0f, &cfg))
        io.Fonts->AddFontDefault(&cfg);
    if (!io.Fonts->AddFontFromFileTTF("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14.0f, &mono_cfg))
        io.Fonts->AddFontDefault(&mono_cfg);
#endif

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
