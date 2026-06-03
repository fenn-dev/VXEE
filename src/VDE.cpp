#include "include/VDE.hpp"
#include "include/VXE_Instructions.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <mutex>
#include <thread>

#undef ARCH_64_BIT
#undef ARCH_32_BIT
#undef WIN
#undef UNIX

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #define WIN 1
    #define UNIX 0
#else
    #include <sys/mman.h>
    #include <unistd.h>
    #define WIN 0
    #define UNIX 1
#endif

#if defined(_M_ARM64) || defined(__aarch64__)
    constexpr uint8_t ARCHTYP = 3; // ARM64
#elif defined(_M_X64) || defined(__x86_64__)
    constexpr uint8_t ARCHTYP = 2; // x86_64
#else
    constexpr uint8_t ARCHTYP = 1; // x86
#endif

std::mutex g_TaskMapMutex;

// Extern from main.cpp to handle output redirection
#if WIN
    extern thread_local HANDLE g_vxe_ipc_out;
#else
    extern thread_local int g_vxe_ipc_out;
#endif

uint64_t native_vxe_alloc(VXE_Context* ctx, uint64_t size) {
    #if WIN
    return reinterpret_cast<uint64_t>(VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    #else
    void* mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    return (mem == MAP_FAILED) ? 0 : reinterpret_cast<uint64_t>(mem);
    #endif
}

void native_vxe_free(VXE_Context* ctx, uint64_t addr) {
    if (!addr) return;
    #if WIN
    VirtualFree(reinterpret_cast<LPVOID>(addr), 0, MEM_RELEASE);
    #else
    // Size tracking would go here for munmap if managing raw POSIX page allocations
    #endif
}

uint64_t native_vxe_write(VXE_Context* ctx, uint64_t handle, uint64_t buffer, uint64_t len) {
    #if WIN
    DWORD written = 0;
    // Redirect handle 1 (stdout) and 2 (stderr) to IPC if available
    HANDLE h = ((handle == 1 || handle == 2) && g_vxe_ipc_out != INVALID_HANDLE_VALUE) ? 
               g_vxe_ipc_out : 
               (handle == 1) ? GetStdHandle(STD_OUTPUT_HANDLE) : 
               (handle == 2) ? GetStdHandle(STD_ERROR_HANDLE) : 
               reinterpret_cast<HANDLE>(handle);

    WriteFile(h, reinterpret_cast<LPCVOID>(buffer), static_cast<DWORD>(len), &written, NULL);
    return static_cast<uint64_t>(written);
    #else
    if ((handle == 1 || handle == 2) && g_vxe_ipc_out != -1) {
        return write(g_vxe_ipc_out, reinterpret_cast<const void*>(buffer), len);
    }
    return write(static_cast<int>(handle), reinterpret_cast<const void*>(buffer), len);
    #endif
}

uint64_t native_vxe_read(VXE_Context* ctx, uint64_t handle, uint64_t buffer, uint64_t len) {
    #if WIN
    DWORD read = 0;
    HANDLE h = (handle == 0) ? GetStdHandle(STD_INPUT_HANDLE) : 
               reinterpret_cast<HANDLE>(handle);

    ReadFile(h, reinterpret_cast<LPVOID>(buffer), static_cast<DWORD>(len), &read, NULL);
    return static_cast<uint64_t>(read);
    #else
    return read(static_cast<int>(handle), reinterpret_cast<void*>(buffer), len);
    #endif
}

uint64_t native_vxe_get_args(VXE_Context* ctx) {
    #if WIN
    return reinterpret_cast<uint64_t>(GetCommandLineA());
    #else
    return 0; // Handled via host environment variables in custom system shells
    #endif
}

#if WIN
void EnsureWindowsFileAssociation() {
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        return; 
    }

    // Added --wait so that file-association launches block until the bytecode finishes
    std::string commandValue = std::string("\"") + exePath + "\" --wait \"%1\"";

    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Classes\\.vxe", 0, NULL, 
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "", 0, REG_SZ, reinterpret_cast<const BYTE*>("Vulpine.Runtime"), 16);
        RegCloseKey(hKey);
    }

    std::string shellKeyPath = "Software\\Classes\\Vulpine.Runtime\\shell\\open\\command";
    if (RegCreateKeyExA(HKEY_CURRENT_USER, shellKeyPath.c_str(), 0, NULL, 
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        
        RegSetValueExA(hKey, "", 0, REG_SZ, 
                       reinterpret_cast<const BYTE*>(commandValue.c_str()), 
                       static_cast<DWORD>(commandValue.length() + 1));
        RegCloseKey(hKey);
    }
}
#endif

auto VDE::Initialize() -> int {
    #if WIN
    EnsureWindowsFileAssociation();
    #endif
    isidling = false;
    m_debugMode = false; // Default to non-debug mode
    return 0;
}

auto VDE::EnterBackgroundIdlingMode() -> int {
    isidling = true;
    return 0;
}

auto VDE::ExitBackgroundIdlingMode() -> int {
    if (isidling) {
        isidling = false;
    }
    return 0;
}

auto VDE::LoadAndExecute(std::string path, bool wait, bool debugMode) -> int {
    m_debugMode = debugMode; // Set debug mode for this execution
    ExitBackgroundIdlingMode();
    
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return -1;

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    if (fileSize < 48) return -2; // Header is too small

    std::vector<uint8_t> localBytes(fileSize);
    file.read(reinterpret_cast<char*>(localBytes.data()), fileSize);
    file.close();

    // 1. Parse Global Header (0x30 bytes / 48 decimal)
    // Offset 0x00: Magic (skip)
    // Offset 0x04: archNum (DWORD)
    uint32_t archCounts = 0;
    for (int b = 0; b < 4; ++b) archCounts |= (static_cast<uint32_t>(localBytes[0x04 + b]) << (b * 8));

    // 2. Locate Arch Table (starts at 0x30)
    size_t cursor = 0x30;
    struct FullSlice { uint8_t id; uint64_t off; uint64_t size; uint64_t entry; } targetSlice{0, 0, 0, 0};
    bool sliceFound = false;
    const uint8_t hostArchTarget = ARCHTYP;

    for (uint32_t i = 0; i < archCounts; ++i) {
        // Arch Table Entry is exactly 16 bytes
        uint8_t archID = localBytes[cursor];
        
        // Read codeOffset (4 bytes)
        uint64_t cOff = 0;
        for (int b = 0; b < 4; ++b) cOff |= (static_cast<uint64_t>(localBytes[cursor + 2 + b]) << (b * 8));

        // Read codeSize (4 bytes)
        uint64_t cSize = 0;
        for (int b = 0; b < 4; ++b) cSize |= (static_cast<uint64_t>(localBytes[cursor + 6 + b]) << (b * 8));

        // Read entryPoint (4 bytes)
        uint64_t ePoint = 0;
        for (int b = 0; b < 4; ++b) ePoint |= (static_cast<uint64_t>(localBytes[cursor + 10 + b]) << (b * 8));

        if (archID == hostArchTarget) {
            targetSlice = {archID, cOff, cSize, ePoint};
            sliceFound = true;
        }
        cursor += 16; // Move to next 16-byte entry
    }

    if (!sliceFound) {
        uint8_t foundID = (localBytes.size() >= 0x31) ? localBytes[0x30] : 0;
    }

    if (!sliceFound) return -4;

    // 3. Setup Task
    uint64_t taskId;
    // Load the entire bytecode segment for this architecture
    const uint8_t* codePayloadPtr = localBytes.data() + targetSlice.off;
    size_t codePayloadSize = targetSlice.size;

    {
        std::lock_guard<std::mutex> lock(g_TaskMapMutex);
        taskId = nextTaskId++;
        RunningTask& newTask = activeTasks[taskId];
        newTask.taskId = taskId;
        newTask.programName = path;
        newTask.binaryBuffer = std::move(localBytes);
    }

    // 4. Execution
    if (wait) {
        return this->run(codePayloadPtr, codePayloadSize, targetSlice.entry, taskId, m_debugMode);
    } else {
        std::thread t(&VDE::run, this, codePayloadPtr, codePayloadSize, targetSlice.entry, taskId, m_debugMode);
        t.detach(); // Detach the thread if not waiting
        return 0;
    }
}

auto VDE::Shutdown() -> int {
    return 0;
}

auto VDE::run(const uint8_t* codeBuffer, size_t size, uint64_t entryOffset, uint64_t taskId, bool debugMode) -> int {
    if (size == 0 || !codeBuffer) return -1;

    VXE_Context ctx;
    ctx.vxe_alloc    = reinterpret_cast<decltype(ctx.vxe_alloc)>(native_vxe_alloc);
    ctx.vxe_free     = reinterpret_cast<decltype(ctx.vxe_free)>(native_vxe_free);
    ctx.vxe_write    = reinterpret_cast<decltype(ctx.vxe_write)>(native_vxe_write);
    ctx.vxe_read     = reinterpret_cast<decltype(ctx.vxe_read)>(native_vxe_read);
    ctx.vxe_get_args = reinterpret_cast<decltype(ctx.vxe_get_args)>(native_vxe_get_args);

    #if UNIX
    void* execMem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    #else
    void* execMem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    #endif
    std::memcpy(execMem, codeBuffer, size);

    uint64_t final_exit_code = 0;

    void* entryAddr = (uint8_t*)execMem + entryOffset;

    #if defined(_M_X64) || defined(__x86_64__)
    unsigned char thunk_code[] = {
        0x53,                               // push rbx (Preserve Host State)
        0x57,                               // push rdi
        0x56,                               // push rsi
        0x41, 0x54,                         // push r12 (Fennec uses these for vars)
        0x41, 0x55,                         // push r13
        0x41, 0x56,                         // push r14
        0x41, 0x57,                         // push r15 (Context Pointer - MUST PRESERVE)
        0x48, 0x89, 0xCB,                   // mov rbx, rcx (rbx = context)
        0x48, 0x89, 0xD0,                   // mov rax, rdx (rax = entry)
        0x48, 0x89, 0xDF,                   // mov rdi, rbx (arg1 = context)
        0x48, 0x83, 0xEC, 0x20,             // sub rsp, 32 (Shadow space)
        0xFF, 0xD0,                         // call rax (Execute Bytecode)
        0x48, 0x83, 0xC4, 0x20,             // add rsp, 32
        0x41, 0x5F,                         // pop r15
        0x41, 0x5E,                         // pop r14 (Restore Host State)
        0x41, 0x5D,                         // pop r13
        0x41, 0x5C,                         // pop r12
        0x5E,                               // pop rsi
        0x5F,                               // pop rdi
        0x5B,                               // pop rbx
        0xC3                                // ret
    };

    #if UNIX
    void* thunk_mem = mmap(nullptr, sizeof(thunk_code), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    #else
    void* thunk_mem = VirtualAlloc(nullptr, sizeof(thunk_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    #endif

    if (thunk_mem) {
        std::memcpy(thunk_mem, thunk_code, sizeof(thunk_code));
        
        using thunk_entry_t = uint64_t(*)(void* ctx, void* entry);
        thunk_entry_t run_bridge = reinterpret_cast<thunk_entry_t>(thunk_mem);
        
        if (debugMode) {
            std::printf("[VDE Engine] Executing bytecode at %p...\n", execMem);
        }
        final_exit_code = run_bridge(&ctx, entryAddr);
        if (debugMode) {
            std::printf("[VDE Engine] Execution finished. Result: %llu\n", final_exit_code);
        }
        
        #if UNIX
        munmap(thunk_mem, sizeof(thunk_code));
        #else
        VirtualFree(thunk_mem, 0, MEM_RELEASE);
        #endif
    }
    #else
    using vxe_entry_t = uint64_t(*)(void* ctx);
    vxe_entry_t bin_entry = reinterpret_cast<vxe_entry_t>(execMem);
    final_exit_code = bin_entry(&ctx);
    // For non-x86_64 or fallback
    final_exit_code = 0;
    #endif

    #if UNIX
    munmap(execMem, size);
    #else
    VirtualFree(execMem, 0, MEM_RELEASE);
    #endif
    
    // --- Safe Memory Unloading & Task Map Cleanup ---
    {
        std::lock_guard<std::mutex> lock(g_TaskMapMutex);
        activeTasks.erase(taskId);
    }

    return static_cast<int>(final_exit_code);
    return static_cast<int32_t>(final_exit_code);
}