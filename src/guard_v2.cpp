#include "common.hpp"
#include "guard.hpp"

namespace guard {
// V2: resolves symlinks for the part that exists, normalizes the rest.
// Missing files are tolerated; still check-then-use (racy).
bool is_allowed_v2(const std::string& root, const std::string& user_path) {
    using namespace detail;
    if (bad_input(user_path)) return false;
    try {
        std::error_code ec;
        fs::path r = fs::weakly_canonical(fs::path(root), ec);
        if (ec) return false;
        fs::path p = fs::weakly_canonical(fs::path(root) / user_path, ec);
        if (ec) return false;
        if (strict_missing() && !fs::exists(p, ec)) return false;  // missing/dangling = deny
        return is_within(r, p);
    } catch (...) {
        return false;
    }
}
}  // namespace guard
