# Hyperion

A native x86/x64 disassembler and binary analysis tool for Windows PE files. Built from scratch in C++20 with ImGui.

[![Discord](https://img.shields.io/discord/placeholder?label=Discord&logo=discord&color=5865F2)](https://discord.gg/yjym2b7A)
[![GitHub](https://img.shields.io/github/stars/mylovereturns/hyperion-disassembler?style=flat&label=Stars)](https://github.com/mylovereturns/hyperion-disassembler)

Hyperion performs recursive descent disassembly, automatic function detection, control flow graph construction, cross-reference analysis, and basic decompilation — all parallelized across available cores using a task-based scheduler.

<img width="3430" height="1367" alt="image" src="https://github.com/user-attachments/assets/aeba409d-9437-47cf-bc76-a648f32c1432" />


## Community

- [Discord](https://discord.gg/yjym2b7A) — discussion, bug reports, feature requests
- [GitHub](https://github.com/mylovereturns/hyperion-disassembler) — source, issues, releases

## Why

Existing free disassemblers are either painfully slow, lack interactivity, or require you to fight the UI to get basic tasks done. Hyperion is designed to be fast, responsive, and familiar to anyone who has used IDA. The goal is a practical daily-driver RE tool that doesn't cost $2000/year.

## How It Works

The analysis pipeline runs in stages, each feeding the next:

1. **PE Loading** — Custom parser handles DOS/NT headers, sections, imports, exports, and relocations without external dependencies.
2. **Linear Sweep** — Every executable section gets decoded in parallel (one thread per section via the worker pool).
3. **Recursive Descent** — Starting from the entry point and all exports, follows control flow to discover code that linear sweep misses.
4. **Function Detection** — Identifies functions from call targets, prologue patterns, and export entries.
5. **Signature Matching** — ~100 byte-pattern signatures for common MSVC CRT functions (security cookies, exception handlers, string ops, alloc/free, etc.). Also loads IDA FLIRT .sig file metadata for reference.
6. **CFG Construction** — Builds basic blocks and edges per function, computes predecessors.
7. **Cross-References** — Code xrefs (call/jmp targets) and data xrefs (memory operands, immediates pointing into the image).
8. **String Detection** — ASCII and UTF-16LE strings extracted from data sections.

All of this runs on a thread pool with a DAG-based task scheduler — typically finishes in under 2 seconds for a ~2MB binary.

## Features

- Full PE32/PE64 support (exe, dll, sys)
- Zydis-based instruction decoding
- Dockable panel UI with IDA-like dark theme
- Disassembly view with color-coded mnemonics, auto-comments, xref badges
- Hex editor with byte patching, pattern highlighting, keyboard navigation
- Pseudo-code generation (simplified C-like output per function)
- Control flow graph visualization with layered layout
- Functions panel with filter/search
- Cross-reference popup (X key) and panel with caller/callee resolution
- String references with xref counts
- Import/export browser
- Entropy heatmap for identifying packed/encrypted regions
- Call graph view (callers/callees of selected function)
- Binary pattern search with wildcards (`4C 8B ?? 48 89`)
- Text search across names, strings, comments
- Immediate value search
- Full rebase (including to 0x0) with delta or absolute mode
- Bookmarks
- Undo/redo for renames, comments, patches
- NOP-out and patched binary export
- IDAPython script export
- Project save/load (.hdb format)
- Drag-and-drop file loading

## Keybinds

These mirror IDA defaults.

| Key | Action |
|-----|--------|
| G | Go to address |
| N | Rename |
| ; | Comment |
| X | Cross-references |
| D | Define data (cycle byte/word/dword/qword) |
| A | Define ASCII string |
| U | Undefine |
| C | Force as code |
| H | Toggle hex/decimal |
| Enter | Follow branch/call |
| Escape | Navigate back |
| Space / Tab | Sync graph + pseudo-code |
| Ctrl+O | Open |
| Ctrl+S | Save project |
| Ctrl+F | Search |
| Alt+B | Binary pattern search |
| Ctrl+Z/Y | Undo/Redo |
| Ctrl+B | Bookmark |
| Ctrl+M | Bookmarks list |
| Alt+Left/Right | Navigate back/forward |
| Double-click | Follow target |
| Right-click | Context menu |

## Building

Requires CMake 3.25+, vcpkg, and a C++20 compiler (MSVC 2022+ recommended).

```
git clone --recursive https://github.com/mylovereturns/hyperion-disassembler
cd hyperion
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

Dependencies are pulled automatically via vcpkg: imgui (docking), glfw, zydis, spdlog, fmt, zlib.

## Project Status

This is an active work-in-progress. Currently functional for static analysis of Windows PE binaries. Not a replacement for IDA on day one, but it's getting there.

Things on the roadmap:
- Full FLIRT .sig tree parsing (currently extracts metadata + names only)
- Type system (structs, enums, typedefs)
- Stack frame view
- Scripting (Lua or Python)
- Plugin API
- Debugger integration
- Multi-file / library analysis

## License

MIT
