cmake_minimum_required(VERSION 3.25)
project(Hyperion VERSION 0.1.7 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# static CRT on MSVC
if(MSVC)
    if(NOT CMAKE_MSVC_RUNTIME_LIBRARY)
        if(VCPKG_TARGET_TRIPLET MATCHES "static")
            set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        endif()
    endif()
    add_compile_options(/W4 /MP /permissive-)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(APPLE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -framework OpenGL -framework Cocoa -framework IOKit -framework CoreVideo")
    endif()
endif()

find_package(imgui CONFIG REQUIRED)
find_package(glfw3 CONFIG REQUIRED)
find_package(OpenGL REQUIRED)
find_package(zydis CONFIG REQUIRED)
find_package(capstone CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Lua REQUIRED)

file(GLOB_RECURSE HYPERION_SOURCES
    "src/*.cpp"
    "src/*.h"
)

if(NOT WIN32)
    list(FILTER HYPERION_SOURCES EXCLUDE REGEX "src/debugger/")
endif()

add_executable(${PROJECT_NAME} ${HYPERION_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${LUA_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    imgui::imgui
    glfw
    OpenGL::GL
    Zydis::Zydis
    capstone::capstone
    spdlog::spdlog
    fmt::fmt
    ZLIB::ZLIB
    ${LUA_LIBRARIES}
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE dbghelp comdlg32)
endif()

if(APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE "-framework Cocoa" "-framework IOKit")
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE
    HYPERION_VERSION="${PROJECT_VERSION}"
    HYPERION_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    HYPERION_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    HYPERION_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)

target_precompile_headers(${PROJECT_NAME} PRIVATE
    <cstdint>
    <string>
    <vector>
    <unordered_map>
    <memory>
    <algorithm>
    <thread>
    <mutex>
    <atomic>
    <functional>
    <span>
)
