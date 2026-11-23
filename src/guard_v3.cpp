#include "common.hpp"
#include "guard.hpp"

namespace guard {
// V3: fully resolves every symlink; the path must exist. Missing files are
// denied. Still check-then-use (racy).
bool is_allowed_v3(const std::string& root, const std::string& user_path) {
    using namespace detail;
    if (bad_input(user_path)) return false;
    try {
        std::error_code ec;
        fs::path r = fs::canonical(fs::path(root), ec);
        if (ec) return false;
        fs::path p = fs::canonical(fs::path(root) / user_path, ec);
        if (ec) return false;
        return is_within(r, p);
    } catch (...) {
        return false;
    }
}
}  // namespace guard
