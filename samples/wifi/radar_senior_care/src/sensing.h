/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef RADAR_CARE_SENSING_H_
#define RADAR_CARE_SENSING_H_

#include "care.h"

/**
 * @brief Callback invoked by the sensing backend for each produced event.
 *
 * Called from the sensing thread context. The handler must be quick and must
 * copy any data it needs (the event is not valid after the call returns).
 */
typedef void (*sensing_event_cb_t)(const struct care_event *evt);

/**
 * @brief Start the sensing backend.
 *
 * Implemented by exactly one backend (synthetic or A121), selected at build
 * time via CONFIG_RADAR_CARE_SENSOR_*. The backend spawns its own thread and
 * delivers events through @p cb.
 *
 * @return 0 on success, negative errno otherwise.
 */
int sensing_start(sensing_event_cb_t cb);

/**
 * @brief Acknowledge / clear a latched fall.
 *
 * Called when the dashboard acknowledges a fall alert (server -> device command
 * on care/<site>/<room>/cmd). The backend clears any latched fall state and
 * emits a CARE_FALL_NONE so device and dashboard agree. Safe to call from any
 * thread; the backend picks it up on its next processing iteration.
 */
void sensing_ack_fall(void);

#endif /* RADAR_CARE_SENSING_H_ */
