// Local TOCTOU demo on its OWN temp fixtures (never touches other paths).
// Shows that "check, then open by name" can race, while openat2(BENEATH) cannot.
// Usage: toctou_race [iterations=200000] [runs=1]
#include "../src/guard.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using Check = std::function<bool(const std::string&, const std::string&)>;

struct Stats {
    long attempts = 0;
    long allowed = 0;
    long opened = 0;
    long escapes = 0;
};

// C3: Reliable temporary directory cleanup
static std::string g_temp_dir;
static void cleanup_temp() {
    if (!g_temp_dir.empty()) {
        std::error_code ec;
        fs::remove_all(g_temp_dir, ec);
        g_temp_dir.clear();
    }
}

static void signal_handler(int sig) {
    cleanup_temp();
    _exit(128 + sig);
}

static void attacker(const std::string& root, std::atomic<bool>& stop) {
    const std::string target = root + "/target", tmp = root + "/.swap_tmp", safe = root + "/safe.txt";
    while (!stop.load(std::memory_order_relaxed)) {
        unlink(tmp.c_str());
        if (symlink("../outside/secret.txt", tmp.c_str()) == 0) rename(tmp.c_str(), target.c_str());
        unlink(tmp.c_str());
        if (link(safe.c_str(), tmp.c_str()) == 0) rename(tmp.c_str(), target.c_str());
    }
}

static bool read_is_outside(int fd) {
    char buf[32] = {};
    ssize_t n = read(fd, buf, sizeof buf - 1);
    return n > 0 && std::strncmp(buf, "OUTSIDE", 7) == 0;
}

static Stats check_then_open(const Check& check, const std::string& root, long iters) {
    Stats s;
    const std::string path = root + "/target";
    for (long i = 0; i < iters; ++i) {
        s.attempts++;
        if (!check(root, "target")) continue;         // time of CHECK
        s.allowed++;
        int fd = open(path.c_str(), O_RDONLY);        // time of USE (path resolved again)
        if (fd < 0) continue;
        s.opened++;
        if (read_is_outside(fd)) s.escapes++;
        close(fd);
    }
    return s;
}

static Stats beneath_only(const std::string& root, long iters) {
    Stats s;
    for (long i = 0; i < iters; ++i) {
        s.attempts++;
        int fd = guard::open_beneath(root, "target"); // check + open in one syscall
        if (fd < 0) continue;
        s.allowed++;
        s.opened++;
        if (read_is_outside(fd)) s.escapes++;
        close(fd);
    }
    return s;
}

int main(int argc, char** argv) {
    long iters = argc > 1 ? std::atol(argv[1]) : 20000;
    int runs = argc > 2 ? std::atoi(argv[2]) : 1;
    if (iters < 1000) iters = 1000;
    if (runs < 1) runs = 1;
    if (runs > 5) runs = 5;

    // Register cleanup handlers
    std::atexit(cleanup_temp);
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    std::signal(SIGHUP, signal_handler);

    // C2: Environment identification
    struct utsname uts{};
    uname(&uts);
    std::string kernel = uts.release;
    bool is_wsl = (kernel.find("microsoft") != std::string::npos ||
                   kernel.find("WSL") != std::string::npos ||
                   fs::exists("/proc/sys/fs/binfmt_misc/WSLInterop"));
    unsigned int cpu_count = std::thread::hardware_concurrency();
    if (cpu_count == 0) cpu_count = 1;

#if defined(__GNUC__)
    std::string compiler = "g++ " + std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__) + "." + std::to_string(__GNUC_PATCHLEVEL__);
#else
    std::string compiler = "unknown";
#endif

    std::printf("================ TOCTOU Race Condition Evaluation ================\n");
    std::printf("Environment: Kernel=%s | Compiler=%s | CPUs=%u | WSL=%s\n",
                kernel.c_str(), compiler.c_str(), cpu_count, is_wsl ? "Yes (WSL2)" : "Native Linux");
    std::printf("Configuration: %ld iterations per run, %d repeated run(s)\n\n", iters, runs);

    std::string tmpl = (fs::temp_directory_path() / "toctou_XXXXXX").string();
    if (!mkdtemp(tmpl.data())) { std::perror("mkdtemp"); return 1; }
    g_temp_dir = tmpl;

    fs::path work = fs::canonical(tmpl);
    fs::create_directories(work / "root");
    fs::create_directories(work / "outside");
    std::ofstream(work / "root" / "safe.txt") << "inside\n";
    std::ofstream(work / "outside" / "secret.txt") << "OUTSIDE_SECRET\n";
    const std::string root = (work / "root").string();
    if (link((root + "/safe.txt").c_str(), (root + "/target").c_str()) != 0) {
        std::perror("link");
        cleanup_temp();
        return 1;
    }

    struct VariantRow {
        std::string name;
        long attempts_total = 0;
        long allowed_total = 0;
        long opened_total = 0;
        std::vector<long> escapes_per_run;
    };

    std::vector<VariantRow> rows = {
        {"V2 weakly_canonical", 0, 0, 0, {}},
        {"V3 canonical",        0, 0, 0, {}},
        {"V4 openat2 BENEATH",  0, 0, 0, {}}
    };

    for (int r = 0; r < runs; ++r) {
        auto run_victim = [&](const char* name, std::function<Stats()> victim, VariantRow& vr) {
            std::atomic<bool> stop{false};
            std::thread atk(attacker, std::cref(root), std::ref(stop));
            Stats s = victim();
            stop = true;
            atk.join();
            vr.attempts_total += s.attempts;
            vr.allowed_total += s.allowed;
            vr.opened_total += s.opened;
            vr.escapes_per_run.push_back(s.escapes);
            (void)name;
        };

        run_victim("V2 weakly_canonical", [&] { return check_then_open(guard::is_allowed_v2, root, iters); }, rows[0]);
        run_victim("V3 canonical",        [&] { return check_then_open(guard::is_allowed_v3, root, iters); }, rows[1]);
        run_victim("V4 openat2 BENEATH",  [&] { return beneath_only(root, iters); }, rows[2]);
    }

    // Output human-readable summary
    if (runs == 1) {
        std::printf("%-20s %10s %10s %10s %10s\n", "Variant", "Attempts", "Allowed", "Opened", "Escapes");
        for (const auto& r : rows) {
            std::printf("%-20s %10ld %10ld %10ld %10ld\n",
                        r.name.c_str(), r.attempts_total, r.allowed_total, r.opened_total, r.escapes_per_run[0]);
        }
    } else {
        std::printf("%-20s %10s %10s %10s %6s %6s %6s  %s\n",
                    "Variant", "Attempts", "Allowed", "Opened", "Min", "Max", "Total", "Escapes/Run");
        for (const auto& r : rows) {
            long min_esc = *std::min_element(r.escapes_per_run.begin(), r.escapes_per_run.end());
            long max_esc = *std::max_element(r.escapes_per_run.begin(), r.escapes_per_run.end());
            long tot_esc = std::accumulate(r.escapes_per_run.begin(), r.escapes_per_run.end(), 0L);
            std::ostringstream runs_str;
            runs_str << "[";
            for (size_t i = 0; i < r.escapes_per_run.size(); ++i) {
                if (i > 0) runs_str << ", ";
                runs_str << r.escapes_per_run[i];
            }
            runs_str << "]";
            std::printf("%-20s %10ld %10ld %10ld %6ld %6ld %6ld  %s\n",
                        r.name.c_str(), r.attempts_total, r.allowed_total, r.opened_total,
                        min_esc, max_esc, tot_esc, runs_str.str().c_str());
        }
    }

    std::printf("\nEscapes = opened files whose content came from outside the root.\n"
                "Results are PROBABILISTIC: 0 escapes in a run does NOT prove safety.\n"
                "Running multiple iterations exposes intermittent race windows.\n");

    // Output machine-readable JSON for API and automation
    std::ostringstream j;
    j << "JSON_OUTPUT_START\n{\n";
    j << "  \"iterations\": " << iters << ",\n";
    j << "  \"runs\": " << runs << ",\n";
    j << "  \"environment\": {\n";
    j << "    \"kernel\": \"" << kernel << "\",\n";
    j << "    \"compiler\": \"" << compiler << "\",\n";
    j << "    \"cpus\": " << cpu_count << ",\n";
    j << "    \"wsl\": " << (is_wsl ? "true" : "false") << "\n";
    j << "  },\n";
    j << "  \"rows\": [\n";
    for (size_t i = 0; i < rows.size(); ++i) {
        const auto& r = rows[i];
        long min_esc = *std::min_element(r.escapes_per_run.begin(), r.escapes_per_run.end());
        long max_esc = *std::max_element(r.escapes_per_run.begin(), r.escapes_per_run.end());
        long tot_esc = std::accumulate(r.escapes_per_run.begin(), r.escapes_per_run.end(), 0L);

        j << "    {\n";
        j << "      \"variant\": \"" << r.name << "\",\n";
        j << "      \"attempts\": " << r.attempts_total << ",\n";
        j << "      \"allowed\": " << r.allowed_total << ",\n";
        j << "      \"opened\": " << r.opened_total << ",\n";
        j << "      \"escapes\": " << tot_esc << ",\n";
        j << "      \"escapes_min\": " << min_esc << ",\n";
        j << "      \"escapes_max\": " << max_esc << ",\n";
        j << "      \"escapes_total\": " << tot_esc << ",\n";
        j << "      \"runs\": [";
        for (size_t k = 0; k < r.escapes_per_run.size(); ++k) {
            if (k > 0) j << ", ";
            j << r.escapes_per_run[k];
        }
        j << "]\n";
        j << "    }" << (i + 1 < rows.size() ? "," : "") << "\n";
    }
    j << "  ]\n";
    j << "}\nJSON_OUTPUT_END\n";
    std::cout << j.str();

    cleanup_temp();
    return 0;
}
