/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Zephyr port of the Acconeer "acc_integration" OS primitives.
 */

#include <zephyr/kernel.h>

#include "acc_integration.h"

void acc_integration_sleep_us(uint32_t time_usec)
{
	k_busy_wait(time_usec);
}

void acc_integration_sleep_ms(uint32_t time_msec)
{
	k_msleep((int32_t)time_msec);
}

void *acc_integration_mem_alloc(size_t size)
{
	return k_malloc(size);
}

void *acc_integration_mem_calloc(size_t nmemb, size_t size)
{
	return k_calloc(nmemb, size);
}

void acc_integration_mem_free(void *ptr)
{
	k_free(ptr);
}

uint32_t acc_integration_get_time(void)
{
	return k_uptime_get_32();
}
