/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef RADAR_CARE_NET_MQTT_H_
#define RADAR_CARE_NET_MQTT_H_

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Handler for commands received on care/<site>/<room>/cmd.
 *
 * Invoked from the MQTT processing context (see @ref care_mqtt_process). The
 * payload is NUL-terminated; @p len excludes the terminator. Keep it short.
 */
typedef void (*care_cmd_handler_t)(const char *payload, size_t len);

/**
 * @brief Initialise the MQTT telemetry module.
 *
 * @param room_id Stable room/device identifier used in the topic tree and as
 *                the MQTT client id.
 */
void care_mqtt_init(const char *room_id);

/**
 * @brief Register a handler for inbound commands on the cmd topic.
 *
 * Must be called before @ref care_mqtt_connect. Pass NULL to clear.
 */
void care_mqtt_set_cmd_handler(care_cmd_handler_t handler);

/**
 * @brief Connect to the broker, set up LWT, publish retained online status and
 *        subscribe to the command topic. Blocks until connected or failed.
 *
 * @return 0 on success, negative errno otherwise.
 */
int care_mqtt_connect(void);

/** @brief Whether an MQTT session is currently up. */
bool care_mqtt_is_connected(void);

/**
 * @brief Publish a payload to care/<site>/<room>/<subtopic>.
 *
 * @return 0 on success, negative errno otherwise.
 */
int care_mqtt_publish(const char *subtopic, const char *payload, bool retain, int qos);

/**
 * @brief Service the MQTT socket for up to @p timeout_ms.
 *
 * @return 0 on success, negative errno on a connection error.
 */
int care_mqtt_process(int timeout_ms);

/** @brief Tear down the current session. */
void care_mqtt_disconnect(void);

#endif /* RADAR_CARE_NET_MQTT_H_ */
