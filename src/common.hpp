#pragma once
#include <algorithm>
#include <filesystem>
#include <string>

namespace guard::detail {
namespace fs = std::filesystem;

// Input validation shared by V1..V4 (V0 is deliberately naive and skips it).
inline bool bad_input(const std::string& p) {
    return p.empty() || p.find('\0') != std::string::npos || p.size() >= 4096;
}

inline fs::path strip_trailing_sep(fs::path p) {
    if (!p.empty() && !p.has_filename()) p = p.parent_path();
    return p;
}

// Component-wise containment: /a/secure_files_backup is NOT inside /a/secure_files.
inline bool is_within(const fs::path& root_in, const fs::path& p_in) {
    fs::path root = strip_trailing_sep(root_in);
    fs::path p = strip_trailing_sep(p_in);
    auto m = std::mismatch(root.begin(), root.end(), p.begin(), p.end());
    return m.first == root.end();
}

}  // namespace guard::detail
