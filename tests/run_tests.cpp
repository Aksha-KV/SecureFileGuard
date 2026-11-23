// Usage: run_tests [fixtures_dir=fixtures] [csv_path=results/results.csv] [strict|lenient]
#include "../src/guard.hpp"
#include "test_cases.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static std::string shorten(const std::string& s) {
    if (s.size() <= 36) return s;
    return s.substr(0, 28) + "...(len=" + std::to_string(s.size()) + ")";
}

static std::string csv_escape(const std::string& s) {
    std::string o = "\"";
    for (char c : s) { if (c == '"') o += '"'; o += c; }
    return o + "\"";
}

int main(int argc, char** argv) {
    fs::path base = argc > 1 ? argv[1] : "fixtures";
    std::string csv_path = argc > 2 ? argv[2] : "results/results.csv";
    const bool strict = !(argc > 3 && std::string(argv[3]) == "lenient");
    guard::strict_missing() = strict;

    std::error_code ec;
    fs::path root_p = fs::canonical(base / "secure_files", ec);
    if (ec) {
        std::cerr << "Fixtures not found. Run: tools/make_fixtures.sh " << base.string() << "\n";
        return 1;
    }
    const std::string root = root_p.string();
    const auto& variants = guard::all_variants();
    const auto tests = get_test_cases(root, strict);
    const size_t nv = variants.size();

    std::vector<std::vector<bool>> actual(tests.size(), std::vector<bool>(nv));
    for (size_t i = 0; i < tests.size(); ++i) {
        for (size_t v = 0; v < nv; ++v) {
            bool r = false;
            try { r = variants[v].fn(root, tests[i].path); } catch (...) { r = false; }
            actual[i][v] = r;
        }
    }

    // ---- Expected vs Actual table ('*' = differs from expectation) ----
    std::printf("Root: %s\nPolicy: %s\nOracle: realpath(3) (independent POSIX resolution)\n\n",
                root.c_str(), strict ? "STRICT (missing = deny)" : "LENIENT");
    std::printf("%-3s %-10s %-38s %-6s", "ID", "Category", "Path", "Expect");
    for (const auto& v : variants) std::printf(" %-7s", v.id);
    std::printf("\n");
    for (size_t i = 0; i < tests.size(); ++i) {
        std::printf("%-3d %-10s %-38s %-6s", tests[i].id, tests[i].category.c_str(),
                    shorten(tests[i].path.empty() ? "(empty)" : tests[i].path).c_str(),
                    tests[i].expect_allow ? "ALLOW" : "DENY");
        for (size_t v = 0; v < nv; ++v) {
            std::string cell = actual[i][v] ? "ALLOW" : "DENY";
            if (actual[i][v] != tests[i].expect_allow) cell += "*";
            std::printf(" %-7s", cell.c_str());
        }
        std::printf("\n");
    }

    // ---- Case Counts ----
    int n_attack = 0, n_legit = 0, n_type = 0, n_missing = 0;
    for (const auto& t : tests) {
        if (t.is_attack) n_attack++;
        else if (t.is_type_check) n_type++;
        else if (t.is_missing_policy) n_missing++;
        else if (t.expect_allow) n_legit++;
    }

    // ---- Metrics Table ----
    std::printf("\n%-4s %-17s %18s %18s %20s %18s %4s %4s %4s %4s\n",
                "Var", "Technique", "Containment-Safe", "Type-Policy Match",
                "Missing-Policy Match", "AllowRate (Legit)",
                "CF", "TM", "PM", "FB");

    int v4_containment_failures = 0;
    for (size_t v = 0; v < nv; ++v) {
        int attacks_denied = 0, legit_allowed = 0, correct = 0;
        int cf = 0, tm = 0, pm = 0, fb = 0;

        for (size_t i = 0; i < tests.size(); ++i) {
            bool exp = tests[i].expect_allow;
            bool act = actual[i][v];

            if (tests[i].is_attack && !act) attacks_denied++;
            if (tests[i].expect_allow && act) legit_allowed++;
            if (exp == act) correct++;

            if (act != exp) {
                if (!act) {
                    fb++;
                } else {
                    if (tests[i].is_attack) cf++;
                    else if (tests[i].is_type_check) tm++;
                    else pm++;
                }
            }
        }

        if (std::string(variants[v].id) == "V4") {
            v4_containment_failures = cf;
        }

        int containment_safe = n_attack - cf;
        int type_matched = n_type - tm;
        int missing_matched = n_missing - pm;

        double safe_pct = n_attack ? (100.0 * containment_safe / n_attack) : 100.0;
        double type_pct = n_type ? (100.0 * type_matched / n_type) : 100.0;
        double missing_pct = n_missing ? (100.0 * missing_matched / n_missing) : 100.0;
        double allow_pct = n_legit ? (100.0 * legit_allowed / n_legit) : 0.0;

        char buf_safe[32], buf_type[32], buf_miss[32], buf_allow[32];
        std::snprintf(buf_safe, sizeof buf_safe, "%5.1f%% (%2d/%2d)", safe_pct, containment_safe, n_attack);
        std::snprintf(buf_type, sizeof buf_type, "%5.1f%% (%2d/%2d)", type_pct, type_matched, n_type);
        std::snprintf(buf_miss, sizeof buf_miss, "%5.1f%% (%2d/%2d)", missing_pct, missing_matched, n_missing);
        std::snprintf(buf_allow, sizeof buf_allow, "%5.1f%% (%2d/%2d)", allow_pct, legit_allowed, n_legit);

        std::printf("%-4s %-17s %18s %18s %20s %18s %4d %4d %4d %4d\n",
                    variants[v].id, variants[v].name,
                    buf_safe, buf_type, buf_miss, buf_allow,
                    cf, tm, pm, fb);
    }

    std::printf("\nEvaluation breakdown: %d attack cases, %d legitimate cases, %d special type cases, %d missing-policy cases (total %zu tests).\n"
                "ContainmentFail = allowed outside-jail escape (critical security vulnerability).\n"
                "TypeMismatch    = allowed directory or FIFO inside jail (file-type policy disagreement, not escape).\n"
                "PolicyMismatch  = allowed non-existent or syntax-error name under strict policy.\n"
                "FalseBlocks     = denied legitimate regular file inside jail.\n",
                n_attack, n_legit, n_type, n_missing, tests.size());

    // ---- CSV output ----
    fs::path out(csv_path);
    if (out.has_parent_path()) fs::create_directories(out.parent_path());
    std::ofstream f(csv_path);
    f << "variant,technique,test_id,category,path,expected,actual,verdict,containment,type_check,policy_check\n";
    for (size_t i = 0; i < tests.size(); ++i) {
        for (size_t v = 0; v < nv; ++v) {
            bool exp = tests[i].expect_allow, act = actual[i][v];
            std::string verdict, containment = "PASS", type_check = "PASS", policy_check = "PASS";
            if (exp == act) {
                verdict = "correct";
            } else if (!act) {
                verdict = "false_block";
            } else {
                if (tests[i].is_attack) {
                    verdict = "containment_failure";
                    containment = "FAIL";
                } else if (tests[i].is_type_check) {
                    verdict = "type_mismatch";
                    type_check = "FAIL";
                } else {
                    verdict = "policy_mismatch";
                    policy_check = "FAIL";
                }
            }
            f << variants[v].id << ',' << variants[v].name << ',' << tests[i].id << ','
              << tests[i].category << ',' << csv_escape(shorten(tests[i].path)) << ','
              << (exp ? "ALLOW" : "DENY") << ',' << (act ? "ALLOW" : "DENY") << ','
              << verdict << ',' << containment << ',' << type_check << ',' << policy_check << '\n';
        }
    }
    std::printf("\nWrote %s\n", csv_path.c_str());

    // B4: Strict validation - fail if V4 has ANY containment failure
    if (v4_containment_failures > 0) {
        std::fprintf(stderr, "FATAL: V4 openat2 had %d containment failure(s)!\n", v4_containment_failures);
        return 1;
    }

    return 0;
}
