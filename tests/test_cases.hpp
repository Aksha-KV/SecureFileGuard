#pragma once
#include <string>
#include <vector>

struct TestCase {
    int id;
    std::string category;
    std::string path;          // user-supplied path (relative to root unless absolute)
    bool expect_allow;         // policy: should access be allowed?
    bool is_attack = false;    // attempts to escape jail
    bool is_type_check = false; // inside jail, but directory or FIFO
    bool is_missing_policy = false; // missing file or syntax error inside jail
};

// "@ROOT@" in a path is replaced with the absolute jail root.
std::vector<TestCase> get_test_cases(const std::string& root, bool strict);
