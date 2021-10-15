/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_CONFIG_H
#define SANDSTONE_CONFIG_H

// Make sure only one of DEBUG / NDEBUG is defined
#if !defined(DEBUG) && !defined(NDEBUG)
#  define DEBUG 1
#endif
#if defined(DEBUG) && defined(NDEBUG)
#  undef NDEBUG
#elif defined(NDEBUG)
#  define DEBUG 0
#endif
#if DEBUG
#  define SANDSTONE_DEBUG       1
#else
#  define SANDSTONE_DEBUG       0
#endif

#ifndef SANDSTONE_GA
#  define SANDSTONE_GA 0
#endif
#ifndef SANDSTONE_GA_DEV
#  define SANDSTONE_GA_DEV              SANDSTONE_DEBUG
#endif

#ifndef SANDSTONE_SECURE_TMPFILES
#  define SANDSTONE_SECURE_TMPFILES   1
#endif

#ifndef SANDSTONE_NO_LOGGING
#  define SANDSTONE_NO_LOGGING          (SANDSTONE_GA && !SANDSTONE_GA_DEV)
#endif
#ifndef SANDSTONE_I18N_LOGGING
#  define SANDSTONE_I18N_LOGGING        (SANDSTONE_GA && !SANDSTONE_GA_DEV)
#endif

#ifndef SANDSTONE_RESTRICTED_CMDLINE
#  define SANDSTONE_RESTRICTED_CMDLINE  SANDSTONE_GA && !SANDSTONE_DEBUG
#endif

#ifndef SANDSTONE_CHILD_BACKTRACE
#  define SANDSTONE_CHILD_BACKTRACE     ((!SANDSTONE_GA || SANDSTONE_GA_DEV) && !SANDSTONE_NO_LOGGING)
#endif

#ifdef __cplusplus

namespace SandstoneConfig {
static constexpr bool Debug = SANDSTONE_DEBUG;

static constexpr bool GeneralAvailability = SANDSTONE_GA;

// keep alphabetical order, please
static constexpr bool ChildBacktrace = SANDSTONE_CHILD_BACKTRACE;
static constexpr bool I18nLogging = SANDSTONE_I18N_LOGGING;
static constexpr bool NoLogging = SANDSTONE_NO_LOGGING;
static constexpr bool RestrictedCommandLine = SANDSTONE_RESTRICTED_CMDLINE;
static constexpr bool SecureTempFiles = SANDSTONE_SECURE_TMPFILES;
} // namespace SandstoneConfig

#endif /* __cplusplus */

#if !DEBUG
#  undef DEBUG
#endif

#endif /* SANDSTONE_CONFIG_H */
