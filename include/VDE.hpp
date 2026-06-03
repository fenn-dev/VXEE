#include <vector>
#include <string>
#include <cstdint>
#include <thread>
#include <mutex>
#include <unordered_map>


class VDE {
private:
    std::vector<uint8_t> bytes;
    bool isidling = false;
    bool m_debugMode = false;

    struct ArchHeader {
        uint8_t archID;
        uint64_t bytecodeOffset;
        uint64_t bytecodeSize;
    };

    struct RunningTask {
        uint64_t taskId;
        std::string programName;
        std::vector<uint8_t> binaryBuffer;
        void* allocatedExecutableMemory;
        std::thread executionThread;
    };

    std::unordered_map<uint64_t, RunningTask> activeTasks;
    uint64_t nextTaskId = 1;

    auto run(const uint8_t* codeBuffer, size_t size, uint64_t entryOffset, uint64_t taskId, bool debugMode) -> int;

public:
    VDE() = default;
    ~VDE() = default;

    auto Initialize() -> int;
    auto EnterBackgroundIdlingMode() -> int;
    auto ExitBackgroundIdlingMode() -> int;
    auto LoadAndExecute(std::string path, bool wait, bool debugMode) -> int;
    auto Shutdown() -> int;
};