#pragma once
// SecureFileGuard: path-containment strategies.
// Every variant answers: "may user_path be opened if the jail is `root`?"
// `root` must be an absolute, canonical directory path.
#include <cstddef>
#include <string>
#include <vector>

namespace guard {

// Policy: STRICT (default) = a target that cannot be found is DENIED (fail securely).
// LENIENT = a missing file that is still inside the jail is allowed (V2, V4 only).
inline bool& strict_missing() { static bool s = true; return s; }

bool is_allowed_v0(const std::string& root, const std::string& user_path); // naive string prefix
bool is_allowed_v1(const std::string& root, const std::string& user_path); // lexically_normal + component check
bool is_allowed_v2(const std::string& root, const std::string& user_path); // weakly_canonical + component check
bool is_allowed_v3(const std::string& root, const std::string& user_path); // canonical + component check
bool is_allowed_v4(const std::string& root, const std::string& user_path); // openat2(RESOLVE_BENEATH)

// Check-and-open in ONE kernel call (V4 core). Returns an fd or -1 (errno set).
int open_beneath(const std::string& root, const std::string& user_path);

// PRIMARY API: returns an open fd (regular files only) or -1. Callers must use this fd
// and must NOT re-open the path by name afterwards, or the check-then-use race returns.
// The is_allowed_* functions are for the evaluation tests only.
inline int open_guarded(const std::string& root, const std::string& user_path) {
    return open_beneath(root, user_path);
}

struct Variant {
    const char* id;
    const char* name;
    bool (*fn)(const std::string&, const std::string&);
};

inline const std::vector<Variant>& all_variants() {
    static const std::vector<Variant> v = {
        {"V0", "naive prefix", &is_allowed_v0},
        {"V1", "lexically_normal", &is_allowed_v1},
        {"V2", "weakly_canonical", &is_allowed_v2},
        {"V3", "canonical", &is_allowed_v3},
        {"V4", "openat2 BENEATH", &is_allowed_v4},
    };
    return v;
}

}  // namespace guard
