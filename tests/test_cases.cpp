#include "test_cases.hpp"

static std::string subst(std::string s, const std::string& root) {
    const std::string tag = "@ROOT@";
    for (size_t pos; (pos = s.find(tag)) != std::string::npos;) s.replace(pos, tag.size(), root);
    return s;
}

std::vector<TestCase> get_test_cases(const std::string& root, bool strict) {
    // {id, category, path, expect_allow, is_attack, is_type_check, is_missing_policy}
    std::vector<TestCase> t = {
        // Legitimate regular files inside jail
        {1,  "legit",     "notes.txt",                         true,   false, false, false},
        {2,  "legit",     "reports/marks.txt",                 true,   false, false, false},
        {3,  "legit",     "./notes.txt",                       true,   false, false, false},
        {4,  "legit",     "reports/../notes.txt",              true,   false, false, false},
        {5,  "legit",     "a..b.txt",                          true,   false, false, false},
        {6,  "legit",     "internal_link.txt",                 true,   false, false, false}, // symlink inside
        // Traversal attacks (escape jail)
        {7,  "traversal", "../outside_secret.txt",             false,  true,  false, false},
        {8,  "traversal", "../../etc/passwd",                  false,  true,  false, false},
        {9,  "traversal", "reports/../../outside_secret.txt",  false,  true,  false, false},
        {10, "traversal", "../../../../../../../../etc/passwd", false, true,  false, false},
        // Absolute path outside vs inside
        {11, "absolute",  "/etc/passwd",                       false,  true,  false, false},
        {12, "absolute",  "@ROOT@/notes.txt",                  true,   false, false, false},
        // Sibling prefix confusion attack
        {13, "prefix",    "../secure_files_backup/private.txt", false, true,  false, false},
        // Symlink escape attacks
        {14, "symlink",   "link_to_outside_file",              false,  true,  false, false},
        {15, "symlink",   "link_to_outside_dir/secret.txt",    false,  true,  false, false},
        {16, "symlink",   "chain_a",                           false,  true,  false, false},
        // Error / edge cases (missing, syntax)
        {17, "error",     "missing.txt",                       !strict, false, false, true},
        {18, "error",     "broken_link",                       false,  true,  false, false}, // dangling link pointing outside
        {19, "error",     "",                                  false,  false, false, true},
        {20, "error",     std::string(5000, 'a'),              false,  false, false, true},
        // Special files inside jail (file-type policy, NOT attacks)
        {21, "special",   ".",                                 false,  false, true,  false}, // directory
        {22, "special",   "reports",                           false,  false, true,  false}, // directory
        {23, "special",   "fifo",                              false,  false, true,  false}, // FIFO inside jail
        // More legit / attacks / special
        {24, "legit",     "reports//marks.txt",                true,   false, false, false},
        {25, "traversal", "notes.txt/../../outside_secret.txt", false, true,  false, false},
        {26, "symlink",   "loop_a",                            false,  true,  false, false}, // symlink loop
        {27, "symlink",   "abs_internal_link",                 true,   false, false, false}, // absolute internal link
        // Missing / un-decoded names (missing-file policy)
        {28, "encoded",   "..%2f..%2fetc%2fpasswd",            !strict, false, false, true},
        {29, "encoded",   "..\\..\\etc\\passwd",              !strict, false, false, true},
        {30, "error",     "notes.txt/",                        false,  false, false, true},
        // Edge cases (Part 3 additions)
        {31, "error",     "notes.txt...",                      !strict, false, false, true},  // trailing dots
        {32, "traversal", "//etc/passwd",                      false,  true,  false, false}, // double-slash at start
        {33, "symlink",   "reports/sub_escape",                false,  true,  false, false}, // symlink in subdir pointing up & out
        {34, "traversal", "link_to_reports/../../outside_secret.txt", false, true, false, false}, // dir symlink traversal
        {35, "legit",     []() { std::string s; for (int i = 0; i < 200; ++i) s += "./"; s += "notes.txt"; return s; }(), true, false, false, false}, // deep path (200 components)
        {36, "legit",     "sécurité_🔒.txt",                   true,   false, false, false}, // UTF-8 filename
    };
    for (auto& c : t) c.path = subst(c.path, root);
    return t;
}
