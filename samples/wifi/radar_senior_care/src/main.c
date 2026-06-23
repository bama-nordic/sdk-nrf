/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Senior-care radar monitor: brings up Wi-Fi, starts the sensing backend
 * (synthetic or A121), and streams presence/breathing/fall telemetry to the
 * care dashboard over MQTT.
 */

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/conn_mgr_connectivity.h>
#include <zephyr/net/conn_mgr_monitor.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/net_mgmt.h>

#include <hw_id.h>

#include "net_sample_common.h"

#include "care.h"
#include "net_mqtt.h"
#include "sensing.h"

LOG_MODULE_REGISTER(radar_care, CONFIG_LOG_DEFAULT_LEVEL);

#define L4_FAMILY_EVENT_MASK                                                    \
	(NET_EVENT_L4_IPV4_CONNECTED | NET_EVENT_L4_IPV4_DISCONNECTED |         \
	 NET_EVENT_L4_IPV6_CONNECTED | NET_EVENT_L4_IPV6_DISCONNECTED)

static struct net_mgmt_event_callback l4_family_cb;
static atomic_t ipv4_connected;
static atomic_t ipv6_connected;
static K_SEM_DEFINE(l4_family_changed, 0, 1);

static char room_id[24];

static void l4_family_event_handler(struct net_mgmt_event_callback *cb, uint64_t event,
				    struct net_if *iface)
{
	ARG_UNUSED(cb);
	ARG_UNUSED(iface);

	switch (event) {
	case NET_EVENT_L4_IPV4_CONNECTED:
		atomic_set(&ipv4_connected, 1);
		break;
	case NET_EVENT_L4_IPV4_DISCONNECTED:
		atomic_set(&ipv4_connected, 0);
		break;
	case NET_EVENT_L4_IPV6_CONNECTED:
		atomic_set(&ipv6_connected, 1);
		break;
	case NET_EVENT_L4_IPV6_DISCONNECTED:
		atomic_set(&ipv6_connected, 0);
		break;
	default:
		return;
	}

	k_sem_give(&l4_family_changed);
}

/* Avoid the dual-stack race where L4_CONNECTED fires on IPv6 before IPv4 DHCP
 * binds (see samples/wifi/arp_mqtt). Default broker is IPv4 here.
 */
static void wait_for_ipv4(void)
{
	int64_t deadline = k_uptime_get() + 30000;

	while (atomic_get(&ipv4_connected) == 0) {
		if (k_uptime_get() >= deadline) {
			LOG_WRN("No IPv4 connectivity yet; proceeding anyway");
			return;
		}
		(void)k_sem_take(&l4_family_changed, K_MSEC(500));
	}
}

static void derive_room_id(void)
{
	if (strlen(CONFIG_RADAR_CARE_ROOM_ID) > 0) {
		(void)strncpy(room_id, CONFIG_RADAR_CARE_ROOM_ID, sizeof(room_id) - 1);
		room_id[sizeof(room_id) - 1] = '\0';
		return;
	}

	char hw[HW_ID_LEN];

	if (hw_id_get(hw, sizeof(hw)) == 0 && strlen(hw) >= 12) {
		(void)snprintk(room_id, sizeof(room_id), "room_%s", &hw[8]);
	} else {
		(void)strncpy(room_id, "room_0000", sizeof(room_id));
	}
}

/* Maps a sensing event onto the MQTT topic tree. Runs in sensing context. */
static void on_care_event(const struct care_event *evt)
{
	char payload[256];

	if (care_event_to_json(evt, payload, sizeof(payload)) < 0) {
		LOG_WRN("event serialization failed (type %d)", evt->type);
		return;
	}

	switch (evt->type) {
	case CARE_EVT_PRESENCE:
		(void)care_mqtt_publish("presence", payload, false, 0);
		break;
	case CARE_EVT_BREATHING:
		(void)care_mqtt_publish("breathing", payload, false, 0);
		break;
	case CARE_EVT_WAVEFORM:
		(void)care_mqtt_publish("breathing/wave", payload, false, 0);
		break;
	case CARE_EVT_FALL:
		/* Reliable delivery for alerts. */
		(void)care_mqtt_publish("fall", payload, false, 1);
		break;
	default:
		break;
	}
}

/* Handles commands from the dashboard on care/<site>/<room>/cmd. Runs in the
 * MQTT processing context. Currently supports {"ack_fall": true}.
 */
static void on_command(const char *payload, size_t len)
{
	ARG_UNUSED(len);

	if (strstr(payload, "ack_fall") != NULL && strstr(payload, "true") != NULL) {
		LOG_INF("Fall acknowledged by dashboard");
		sensing_ack_fall();
	}
}

int main(void)
{
	int err;
	int64_t last_status = 0;

	LOG_INF("Senior-care radar monitor starting");

	derive_room_id();
	LOG_INF("Room id: %s", room_id);
	care_mqtt_init(room_id);
	care_mqtt_set_cmd_handler(on_command);

	net_mgmt_init_event_callback(&l4_family_cb, l4_family_event_handler,
				     L4_FAMILY_EVENT_MASK);
	net_mgmt_add_event_callback(&l4_family_cb);

	err = conn_mgr_all_if_up(true);
	if (err) {
		LOG_ERR("conn_mgr_all_if_up: %d", err);
		return err;
	}

	err = conn_mgr_all_if_connect(true);
	if (err) {
		LOG_ERR("conn_mgr_all_if_connect: %d", err);
		return err;
	}

	wait_for_network();
	wait_for_ipv4();

	err = sensing_start(on_care_event);
	if (err) {
		LOG_ERR("sensing_start: %d", err);
		return err;
	}

	for (;;) {
		if (care_mqtt_connect() != 0) {
			LOG_WRN("Broker connect failed; retry in 5 s");
			k_sleep(K_SECONDS(5));
			continue;
		}

		last_status = k_uptime_get();

		while (care_mqtt_is_connected()) {
			if (care_mqtt_process(1000) < 0) {
				break;
			}

			int64_t now = k_uptime_get();

			if (now - last_status >=
			    CONFIG_RADAR_CARE_STATUS_PERIOD_S * 1000) {
				(void)care_mqtt_publish("status",
							"{\"online\":true}", true, 1);
				last_status = now;
			}
		}

		care_mqtt_disconnect();
		k_sleep(K_SECONDS(3));
	}
}
