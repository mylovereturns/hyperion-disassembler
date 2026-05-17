# Hyperion

A native multi-architecture disassembler and binary analysis tool. Supports PE, ELF, Mach-O, and .NET binaries across x86, x64, ARM, ARM64, MIPS, and PPC. Built from scratch in C++20 with ImGui.

[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?logo=discord)](https://discord.gg/yjym2b7A)
[![GitHub](https://img.shields.io/github/stars/Sidenai/hyperion-disassembler?style=flat&label=Stars)](https://github.com/Sidenai/hyperion-disassembler)

Single statically-linked executable. No installer, no runtime dependencies. Under 4MB.

<img width="3436" height="1362" alt="image" src="https://github.com/user-attachments/assets/89ffa137-ed79-4d6a-b9a6-61324192916b" />

## Community

- [Discord](https://discord.gg/yjym2b7A)
- [GitHub](https://github.com/Sidenai/hyperion-disassembler)

## Supported Formats & Architectures

| Format | Architectures |
|--------|--------------|
| PE (exe, dll, sys) | x86, x64 |
| ELF (so, o, executables) | x86, x64, ARM, ARM64, MIPS, PPC |
| Mach-O (dylib, executables, fat/universal) | x64, ARM64 |
| .NET (managed assemblies) | CIL/IL bytecode |

Disassembly: Zydis (x86/x64) + Capstone (ARM, ARM64, MIPS, PPC)

## Features

**Analysis**
- Recursive descent + linear sweep with alignment conflict resolution
- .pdata exception directory for x64 function boundaries
- RTTI C++ class recovery (vtable parsing, method naming, class hierarchy)
- Import thunk detection, switch/jump table resolution
- Vtable detection, global variable detection
- FLIRT signature matching (~100 MSVC CRT patterns)
- Packer detection (UPX, Themida, VMProtect, ASPack, MPRESS)
- PDB symbol loading (auto-detect via DbgHelp)
- DWARF symbol loading (.debug_info for ELF)
- C++ name demangling (MSVC + GCC/Clang)
- Noreturn/tail call/calling convention detection
- Dataflow propagation, indirect call resolution
- Inter-procedural type propagation

**Decompiler**
- Ghidra-style SSA pipeline (p-code lift → SSA → DCE → propagation → structuring → emit)
- x86/x64 and ARM64 decompiler
- Mark-and-sweep dead code elimination
- RTTI-aware output (obj->Class::method())
- STL container recognition (std::string, std::vector, std::shared_ptr)
- Operator overload detection, for-loop reconstruction
- Return value propagation, caller-save argument folding
- Main/WinMain detection with typed parameters
- Symbolic data addresses

**UI**
- 4 themes (Hyperion, IDA, Midnight, Custom) + background image support
- Navigation band (color-coded memory overview, click to navigate)
- Disassembly with color-coded mnemonics, inline string/import annotations, xref badges
- Hex editor with patching, pattern highlight, keyboard navigation
- Pseudo-code panel (F5, copyable)
- Control flow graph with clickable nodes (Space toggles graph/disasm)
- Functions, strings, imports/exports panels with filter and copy
- Cross-reference popup (X key) and tabbed panel
- Entropy heatmap, call graph, stack frame view
- Type system (structs, enums), Classes view (RTTI browser)
- Binary diff, PE header viewer with packer results
- SigMaker (auto-wildcard, 4 output formats, uniqueness test)
- Search (text, binary pattern with wildcards, immediate values)
- Beautify mode (hides noise, shows only function code + key data)
- Context menu: copy as C array, Python bytes, YARA pattern
- Status bar, monospace code fonts, multiple font sizes

**Scripting & Plugins**
- Embedded Lua 5.4 console (View > Script Console)
- Plugin system: drop `.lua` files in `plugins/` folder
- Plugin API: register menu items, hotkeys, analysis callbacks
- Script API: get_name, set_name, get_insn, get_bytes, get_functions, get_xrefs_to, set_comment, goto_addr, patch_byte, get_segments, get_arch, create_function
- See [docs/scripting.md](docs/scripting.md) and [docs/plugins.md](docs/plugins.md)

**Customization**
- Settings panel (Ctrl+,): fonts, colors, keybinds, advanced options
- Editable keybinds (press-to-assign, persisted)
- Custom theme export/import (.hth files)
- `themes/` folder for community theme distribution
- Background image support (png/jpg, opacity slider)
- Window opacity, cursor line color, border radius, scrollbar width, font selector

**Export**
- Patched binary, .asm listing (MASM-style)
- IDAPython script export
- Project save/load (.hdb format)
- Copy as C array / Python / YARA

**Stability**
- All loaders hardened against malformed/malicious binaries (bounds checks, null-termination, overflow guards)
- Thread-safe analysis (atomic handoff to UI)
- Memory optimized (compact instruction storage, flat sorted vectors, zero per-frame allocations)
- Full undo/redo for all operations
- Auto-save every 60 seconds
- Crash-free on minimize/unfocus
- GPU-accelerated entropy heatmap (single texture draw call)
- Resilient settings/database loading (graceful handling of corrupt files)

## Keybinds

| Key | Action |
|-----|--------|
| G | Go to address |
| N | Rename |
| ; | Comment |
| X | Cross-references |
| F5 | Decompile function |
| Space | Toggle disasm/graph |
| D | Define data |
| A | Define string |
| U | Undefine |
| C | Force as code |
| H | Toggle hex/decimal |
| P | Create function |
| Enter | Follow branch/call |
| Escape | Navigate back |
| Shift+F12 | Strings view |
| Ctrl+O | Open |
| Ctrl+S | Save |
| Ctrl+, | Settings |
| Ctrl+F | Search |
| Alt+B | Binary search |
| Ctrl+Z/Y | Undo/Redo |
| Ctrl+Shift+S | Generate signature |

All keybinds are customizable via Settings.

## Building

Requires CMake 3.25+, vcpkg, C++20 compiler (MSVC 2022+, GCC 13+, or Clang 16+).

```bash
git clone https://github.com/Sidenai/hyperion-disassembler
cd hyperion-disassembler
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

For static linking (single exe, no DLLs):
```bash
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=path/to/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release
```

On macOS with Ninja (recommended):
```bash
brew install cmake ninja pkg-config
git clone https://github.com/microsoft/vcpkg.git ~/.vcpkg && ~/.vcpkg/bootstrap-vcpkg.sh
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=~/.vcpkg/scripts/buildsystems/vcpkg.cmake -G Ninja
cmake --build build --config Release
```

Dependencies (pulled via vcpkg): imgui (docking), glfw, zydis, capstone, spdlog, fmt, zlib, lua, stb.

## Platforms

| Platform | Status |
|----------|--------|
| Windows x64 | Full support |
| Linux x64 | Builds, full support |
| macOS (Intel + Apple Silicon) | Builds, full support |

## Status

Active development. Functional for static analysis across all supported formats. Decompiler produces readable C output for x86/x64 and ARM64. RTTI class recovery works on unobfuscated C++ binaries.

Roadmap:
- Debugger integration (attach, breakpoints, anti-detection) — Windows only, in progress
- Collaborative analysis
- More decompiler improvements
- RISC-V support

## License

MIT — see [LICENSE](LICENSE)

Copyright (c) 2026 - present Siden Technologies Inc.
