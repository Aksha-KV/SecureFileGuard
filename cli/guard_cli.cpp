// guard_cli <canonical_root>   -- reads ONE user path from stdin (raw bytes, may contain NUL)
// Prints JSON: every variant's decision + an independent "ground truth" (the oracle).
// Uses realpath(3) for independent resolution.
// Never prints file contents. Never leaks outside-jail paths or types.
#include "guard.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

static std::string jesc(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); o += b; }
                else o += static_cast<char>(c);
        }
    }
    return o;
}

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: guard_cli <canonical_root>  (path on stdin)\n"); return 2; }
    const std::string root = argv[1];
    const std::string path((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    guard::strict_missing() = true;

    // ---- Oracle: independent ground truth resolved via realpath(3) ----
    // Expected ALLOW <=> fully resolved target exists, is a regular file, and lies below root.
    bool expect_allow = false, have_res = false, inside = false, resolved_outside = false;
    std::string reason, kind, resolved;

    if (path.empty()) {
        reason = "empty path";
    } else if (path.find('\0') != std::string::npos) {
        reason = "contains a NUL byte";
    } else if (path.size() >= 4096) {
        reason = "path too long (>= 4096 bytes)";
    } else {
        std::string full_target = (path[0] == '/') ? path : (root + "/" + path);
        char* rres = realpath(full_target.c_str(), nullptr);
        if (!rres) {
            reason = "cannot be resolved";
        } else {
            std::string resolved_path = rres;
            std::free(rres);

            inside = (resolved_path == root) ||
                     (resolved_path.size() > root.size() &&
                      resolved_path.compare(0, root.size(), root) == 0 &&
                      resolved_path[root.size()] == '/');

            if (!inside) {
                resolved_outside = true;
                reason = "resolves OUTSIDE the jail";
                // A1 Fix: Do NOT expose resolved path or file kind for outside-jail targets.
            } else {
                have_res = true;
                resolved = resolved_path;
                struct stat st{};
                if (stat(resolved.c_str(), &st) == 0) {
                    kind = S_ISREG(st.st_mode) ? "regular file" : S_ISDIR(st.st_mode) ? "directory"
                         : S_ISFIFO(st.st_mode) ? "FIFO" : "special file";
                } else {
                    kind = "unknown";
                }

                if (kind != "regular file") {
                    reason = "inside the jail, but it is a " + kind + ", not a regular file";
                } else {
                    expect_allow = true;
                    reason = "a regular file inside the jail";
                }
            }
        }
    }

    std::ostringstream o;
    o << "{\"input_len\":" << path.size() << ",\"expected\":\"" << (expect_allow ? "ALLOW" : "DENY")
      << "\",\"reason\":\"" << jesc(reason) << "\",\"oracle_method\":\"realpath(3)\",\"kind\":";
    if (have_res && !kind.empty()) o << "\"" << jesc(kind) << "\""; else o << "null";
    o << ",\"resolved\":";
    if (have_res && !resolved.empty()) o << "\"" << jesc(resolved) << "\""; else o << "null";
    o << ",\"inside\":";
    if (resolved_outside) o << "false";
    else if (have_res) o << (inside ? "true" : "false");
    else o << "null";

    o << ",\"variants\":[";
    bool first = true;
    for (const auto& v : guard::all_variants()) {
        bool act = false;
        try { act = v.fn(root, path); } catch (...) { act = false; }
        std::string verdict;
        if (act == expect_allow) {
            verdict = "correct";
        } else if (!act) {
            verdict = "false_block";
        } else {
            // Variant allowed an unallowed path: classify the failure
            if (resolved_outside || (!inside && (path.find("..") != std::string::npos || (path.size() > 0 && path[0] == '/')))) {
                verdict = "containment_failure";
            } else if (inside && !kind.empty() && kind != "regular file") {
                verdict = "type_mismatch";
            } else {
                verdict = "policy_mismatch";
            }
        }

        o << (first ? "" : ",") << "{\"id\":\"" << v.id << "\",\"name\":\"" << jesc(v.name)
          << "\",\"decision\":\"" << (act ? "ALLOW" : "DENY") << "\",\"verdict\":\"" << verdict << "\"}";
        first = false;
    }
    o << "]}";
    std::puts(o.str().c_str());
    return 0;
}
