/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Zephyr port of the Acconeer RSS log sink. Routes RSS logs into the Zephyr
 * logging subsystem.
 */

#include <stdarg.h>
#include <stdio.h>

#include <zephyr/logging/log.h>

#include "acc_definitions_common.h"
#include "acc_integration_log.h"

LOG_MODULE_REGISTER(acconeer_rss, CONFIG_LOG_DEFAULT_LEVEL);

#define ACC_LOG_BUFFER_SIZE 160

void acc_integration_log(acc_log_level_t level, const char *module, const char *format, ...)
{
	char buf[ACC_LOG_BUFFER_SIZE];
	va_list ap;

	va_start(ap, format);
	(void)vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);

	switch (level) {
	case ACC_LOG_LEVEL_ERROR:
		LOG_ERR("[%s] %s", module, buf);
		break;
	case ACC_LOG_LEVEL_WARNING:
		LOG_WRN("[%s] %s", module, buf);
		break;
	case ACC_LOG_LEVEL_INFO:
		LOG_INF("[%s] %s", module, buf);
		break;
	case ACC_LOG_LEVEL_VERBOSE:
	case ACC_LOG_LEVEL_DEBUG:
	default:
		LOG_DBG("[%s] %s", module, buf);
		break;
	}
}
