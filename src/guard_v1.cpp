#include "common.hpp"
#include "guard.hpp"

namespace guard {
// V1: purely lexical. Resolves "." and ".." but never touches the filesystem,
// so symlinks inside the root are invisible to it.
bool is_allowed_v1(const std::string& root, const std::string& user_path) {
    using namespace detail;
    if (bad_input(user_path)) return false;
    try {
        fs::path r = fs::path(root).lexically_normal();
        fs::path p = (fs::path(root) / user_path).lexically_normal();
        return is_within(r, p);
    } catch (...) {
        return false;
    }
}
}  // namespace guard
