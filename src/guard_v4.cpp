#include "common.hpp"
#include "guard.hpp"

#include <cerrno>

#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstdint>
#endif

namespace guard {

#ifdef __linux__
namespace {
struct OpenHow {  // layout of struct open_how from <linux/openat2.h>
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};
constexpr uint64_t kResolveNoMagicLinks = 0x02;
constexpr uint64_t kResolveBeneath = 0x08;
#ifndef SYS_openat2
#define SYS_openat2 437
#endif
int sys_openat2(int dirfd, const char* path, const OpenHow& how) {
    return static_cast<int>(syscall(SYS_openat2, dirfd, path, &how, sizeof(how)));
}
}  // namespace

// V4: the kernel resolves the path and refuses to leave `root` (EXDEV),
// so there is no gap between check and use.
int open_beneath(const std::string& root, const std::string& user_path) {
    using namespace detail;
    if (bad_input(user_path)) { errno = EINVAL; return -1; }

    fs::path rel(user_path);
    if (rel.is_absolute()) {
        rel = rel.lexically_relative(fs::path(root));
        if (rel.empty() || *rel.begin() == "..") { errno = EXDEV; return -1; }
    }

    int rootfd = open(root.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) { errno = EINVAL; return -1; }  // bad root, not "missing file"

    OpenHow how{};
    how.flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY;
    how.resolve = kResolveBeneath | kResolveNoMagicLinks;
    int fd = sys_openat2(rootfd, rel.c_str(), how);
    int saved = errno;
    close(rootfd);
    errno = saved;
    if (fd >= 0) {  // file-object policy: regular files only (no dirs, FIFOs, devices)
        struct stat st;
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); errno = EACCES; return -1; }
    }
    return fd;
}

bool is_allowed_v4(const std::string& root, const std::string& user_path) {
    int fd = open_beneath(root, user_path);
    if (fd >= 0) { close(fd); return true; }
    return errno == ENOENT && !strict_missing();  // lenient mode only
}
#else
int open_beneath(const std::string&, const std::string&) { errno = ENOSYS; return -1; }
bool is_allowed_v4(const std::string&, const std::string&) { return false; }
#endif

}  // namespace guard
