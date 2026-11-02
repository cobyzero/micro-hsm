/**
 * CXI logging interface based on util::logging
 * Note that cxi::Log implementation (now deprecated for internal use) uses this in the background
 */

#ifndef CXI_LOGPP_H
#define CXI_LOGPP_H

#include <cxi.h>
#include <util_logpp.h>
#include <utimacros.h>

namespace cxi
{
    CXIAPI util::log::logger& cxi_logger();
    CXIAPI void log_configure(std::string const& logfile, int loglevel, int logsize);
    CXIAPI void log_configure(Config &config);
    CXIAPI std::shared_ptr<util::log::formatter> cxi_formatter();
}

#ifdef DEBUG
#define CXI_LOG_CONTEXT __FILE__, __LINE__, UTI_WHERE
#else
#define CXI_LOG_CONTEXT NULL, 0, UTI_WHERE
#endif

#define CXI_LOG_TRACE(...) cxi_logger().logf(CXI_LOG_CONTEXT, util::log::log_level::trace, __VA_ARGS__)
#define CXI_LOG_DEBUG(...) cxi_logger().logf(CXI_LOG_CONTEXT, util::log::log_level::debug, __VA_ARGS__)
#define CXI_LOG_INFO(...) cxi_logger().logf(CXI_LOG_CONTEXT, util::log::log_level::info, __VA_ARGS__)
#define CXI_LOG_WARN(...) cxi_logger().logf(CXI_LOG_CONTEXT, util::log::log_level::warn, __VA_ARGS__)
#define CXI_LOG_ERROR(...) cxi_logger().logf(CXI_LOG_CONTEXT, util::log::log_level::error, __VA_ARGS__)

#endif //CXI_LOGPP_H
