// ============================================================================
// DEPRECATED - DO NOT USE
// ============================================================================
// This helper bypasses SecurityManager and is a security risk.
// Use SEC.exec() or SEC.exec_timeout() instead.
//
// All code should include "../core/security_manager.hpp" and use:
//   SEC.exec("command", needs_root);
//   SEC.exec_timeout("command", timeout_sec, needs_root);
// ============================================================================

#include "exec.hpp"
#include <stdexcept>

namespace exec {

[[deprecated("Use SEC.exec() instead - this bypasses security validation")]]
std::string run(const std::string& cmd) {
    (void)cmd;
    throw std::runtime_error("exec::run() is deprecated - use SEC.exec()");
}

[[deprecated("Use SEC.exec() instead - this bypasses security validation")]]
Result run_full(const std::string& cmd) {
    (void)cmd;
    throw std::runtime_error("exec::run_full() is deprecated - use SEC.exec()");
}

[[deprecated("Use SEC.exec() instead - this bypasses security validation")]]
Result run_root(const std::string& cmd) {
    (void)cmd;
    throw std::runtime_error("exec::run_root() is deprecated - use SEC.exec()");
}

} // namespace exec
