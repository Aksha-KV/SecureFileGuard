#include "guard.hpp"
#include <filesystem>

namespace guard {
// V0: join and compare as raw strings. Expected to fail on ".." and on
// sibling directories sharing a prefix (secure_files_backup).
bool is_allowed_v0(const std::string& root, const std::string& user_path) {
    std::string joined = (std::filesystem::path(root) / user_path).string();
    return joined.rfind(root, 0) == 0;  // starts_with
}
}  // namespace guard
