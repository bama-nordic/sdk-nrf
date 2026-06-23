/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * MQTT telemetry for the senior-care radar sample. Publish-oriented, with a
 * retained "status" topic + Last-Will-and-Testament so the dashboard can show
 * each room online/offline, and a subscription to a per-room command topic.
 *
 * Connection handling mirrors samples/wifi/arp_mqtt (plain TCP, IPv4/IPv6).
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/socket.h>
#include <zephyr/random/random.h>
#include <zephyr/posix/arpa/inet.h>
#include <zephyr/posix/netdb.h>
#include <zephyr/posix/poll.h>

#if defined(CONFIG_RADAR_CARE_MQTT_TLS)
#include <zephyr/net/tls_credentials.h>
#include "certs/ca_cert.h"
#endif

#include "net_mqtt.h"

LOG_MODULE_REGISTER(care_mqtt, CONFIG_LOG_DEFAULT_LEVEL);

#define MQTT_BUF_SIZE 512
#define TOPIC_MAX     96

static uint8_t rx_buffer[MQTT_BUF_SIZE];
static uint8_t tx_buffer[MQTT_BUF_SIZE];

static struct mqtt_client client_ctx;
static struct sockaddr_storage broker;
static struct pollfd fds[1];
static int nfds;
static volatile bool connected;

static char room_id[24];
static char base_topic[TOPIC_MAX];   /* care/<site>/<room> */
static char status_topic[TOPIC_MAX]; /* base/status (LWT + retained) */
static char cmd_topic[TOPIC_MAX];    /* base/cmd (subscribe) */

static struct mqtt_utf8 will_message;
static struct mqtt_topic will_topic;

static care_cmd_handler_t cmd_handler;

static K_MUTEX_DEFINE(mqtt_lock);

static const char *const WILL_PAYLOAD = "{\"online\":false}";

#if defined(CONFIG_RADAR_CARE_MQTT_TLS)
static const sec_tag_t sec_tag_list[] = {
	CONFIG_RADAR_CARE_MQTT_TLS_SEC_TAG,
};

static int tls_credentials_setup(void)
{
	int err = tls_credential_add(CONFIG_RADAR_CARE_MQTT_TLS_SEC_TAG,
				     TLS_CREDENTIAL_CA_CERTIFICATE, ca_certificate,
				     sizeof(ca_certificate));
	if (err == -EEXIST) {
		return 0;
	}
	if (err < 0) {
		LOG_ERR("Failed to register broker CA cert: %d", err);
	}

	return err;
}
#endif /* CONFIG_RADAR_CARE_MQTT_TLS */

static int build_topics(void)
{
	int n;

	n = snprintk(base_topic, sizeof(base_topic), "care/%s/%s",
		     CONFIG_RADAR_CARE_SITE_ID, room_id);
	if (n < 0 || n >= (int)sizeof(base_topic)) {
		return -ENAMETOOLONG;
	}

	n = snprintk(status_topic, sizeof(status_topic), "%s/status", base_topic);
	if (n < 0 || n >= (int)sizeof(status_topic)) {
		return -ENAMETOOLONG;
	}

	n = snprintk(cmd_topic, sizeof(cmd_topic), "%s/cmd", base_topic);
	if (n < 0 || n >= (int)sizeof(cmd_topic)) {
		return -ENAMETOOLONG;
	}

	return 0;
}

static int broker_addr_setup(void)
{
	struct zsock_addrinfo hints = {
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	struct zsock_addrinfo *res;
	char portstr[8];
	int err;

	(void)memset(&broker, 0, sizeof(broker));

	if (IS_ENABLED(CONFIG_NET_IPV4)) {
		struct sockaddr_in *b4 = (struct sockaddr_in *)&broker;

		b4->sin_family = AF_INET;
		b4->sin_port = htons(CONFIG_RADAR_CARE_BROKER_PORT);
		if (inet_pton(AF_INET, CONFIG_RADAR_CARE_BROKER_HOSTNAME,
			      &b4->sin_addr) == 1) {
			return 0;
		}
	}

	if (IS_ENABLED(CONFIG_NET_IPV6)) {
		struct sockaddr_in6 *b6 = (struct sockaddr_in6 *)&broker;

		b6->sin6_family = AF_INET6;
		b6->sin6_port = htons(CONFIG_RADAR_CARE_BROKER_PORT);
		if (inet_pton(AF_INET6, CONFIG_RADAR_CARE_BROKER_HOSTNAME,
			      &b6->sin6_addr) == 1) {
			return 0;
		}
	}

	(void)snprintk(portstr, sizeof(portstr), "%d", CONFIG_RADAR_CARE_BROKER_PORT);

	err = getaddrinfo(CONFIG_RADAR_CARE_BROKER_HOSTNAME, portstr, &hints, &res);
	if (err != 0 || res == NULL) {
		LOG_ERR("getaddrinfo(%s): %d", CONFIG_RADAR_CARE_BROKER_HOSTNAME, err);
		return -EINVAL;
	}

	(void)memcpy(&broker, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	return 0;
}

static void handle_incoming_publish(struct mqtt_client *client,
				    const struct mqtt_publish_param *pub)
{
	char payload[256];
	size_t payload_len = pub->message.payload.len;
	size_t received = 0;

	if (payload_len >= sizeof(payload)) {
		LOG_WRN("command payload too large (%zu bytes), dropping", payload_len);
		payload_len = sizeof(payload) - 1;
	}

	while (received < payload_len) {
		int ret = mqtt_read_publish_payload_blocking(client, &payload[received],
							     payload_len - received);
		if (ret < 0) {
			LOG_WRN("read command payload failed: %d", ret);
			return;
		}
		received += ret;
	}
	payload[received] = '\0';

	if (pub->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
		struct mqtt_puback_param puback = { .message_id = pub->message_id };

		(void)mqtt_publish_qos1_ack(client, &puback);
	}

	LOG_INF("MQTT command: %s", payload);

	if (cmd_handler != NULL) {
		cmd_handler(payload, received);
	}
}

static void mqtt_evt_handler(struct mqtt_client *const client, const struct mqtt_evt *evt)
{
	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		connected = (evt->result == 0);
		LOG_INF("MQTT %s (%d)", connected ? "connected" : "connect failed",
			evt->result);
		break;
	case MQTT_EVT_DISCONNECT:
		LOG_INF("MQTT disconnected (%d)", evt->result);
		connected = false;
		nfds = 0;
		break;
	case MQTT_EVT_PUBLISH:
		handle_incoming_publish(client, &evt->param.publish);
		break;
	default:
		break;
	}
}

static struct mqtt_utf8 mqtt_user;
static struct mqtt_utf8 mqtt_pass;

static void auth_init(struct mqtt_client *client)
{
	client->password = NULL;
	client->user_name = NULL;

	if (strlen(CONFIG_RADAR_CARE_MQTT_USERNAME) > 0) {
		mqtt_user.utf8 = (uint8_t *)CONFIG_RADAR_CARE_MQTT_USERNAME;
		mqtt_user.size = strlen(CONFIG_RADAR_CARE_MQTT_USERNAME);
		client->user_name = &mqtt_user;

		mqtt_pass.utf8 = (uint8_t *)CONFIG_RADAR_CARE_MQTT_PASSWORD;
		mqtt_pass.size = strlen(CONFIG_RADAR_CARE_MQTT_PASSWORD);
		client->password = &mqtt_pass;

		if (!IS_ENABLED(CONFIG_RADAR_CARE_MQTT_TLS)) {
			LOG_WRN("MQTT auth without TLS: credentials sent in cleartext");
		}
	}
}

static void transport_init(struct mqtt_client *client)
{
#if defined(CONFIG_RADAR_CARE_MQTT_TLS)
	struct mqtt_sec_config *tls = &client->transport.tls.config;
	const char *sni = strlen(CONFIG_RADAR_CARE_MQTT_TLS_HOSTNAME) > 0
				  ? CONFIG_RADAR_CARE_MQTT_TLS_HOSTNAME
				  : CONFIG_RADAR_CARE_BROKER_HOSTNAME;

	client->transport.type = MQTT_TRANSPORT_SECURE;
	tls->peer_verify = CONFIG_RADAR_CARE_MQTT_TLS_PEER_VERIFY;
	tls->cipher_list = NULL;
	tls->sec_tag_list = sec_tag_list;
	tls->sec_tag_count = ARRAY_SIZE(sec_tag_list);
	tls->hostname = sni;
#else
	client->transport.type = MQTT_TRANSPORT_NON_SECURE;
#endif
}

static int transport_socket(const struct mqtt_client *client)
{
#if defined(CONFIG_RADAR_CARE_MQTT_TLS)
	return client->transport.tls.sock;
#else
	return client->transport.tcp.sock;
#endif
}

static void client_init(struct mqtt_client *client)
{
	mqtt_client_init(client);

	client->broker = &broker;
	client->evt_cb = mqtt_evt_handler;
	client->client_id.utf8 = (uint8_t *)room_id;
	client->client_id.size = strlen(room_id);
	client->protocol_version = MQTT_VERSION_3_1_1;

	client->rx_buf = rx_buffer;
	client->rx_buf_size = sizeof(rx_buffer);
	client->tx_buf = tx_buffer;
	client->tx_buf_size = sizeof(tx_buffer);

	auth_init(client);
	transport_init(client);

	/* Last-Will-and-Testament: retained "offline" on the status topic. */
	will_topic.topic.utf8 = (uint8_t *)status_topic;
	will_topic.topic.size = strlen(status_topic);
	will_topic.qos = MQTT_QOS_1_AT_LEAST_ONCE;
	will_message.utf8 = (uint8_t *)WILL_PAYLOAD;
	will_message.size = strlen(WILL_PAYLOAD);
	client->will_topic = &will_topic;
	client->will_message = &will_message;
	client->will_retain = 1U;
}

static int wait_on_socket(int timeout_ms)
{
	if (nfds <= 0) {
		return 0;
	}

	int ret = poll(fds, nfds, timeout_ms);

	if (ret < 0) {
		LOG_ERR("poll: %d", errno);
		return -errno;
	}

	return ret;
}

void care_mqtt_init(const char *id)
{
	(void)strncpy(room_id, id, sizeof(room_id) - 1);
	room_id[sizeof(room_id) - 1] = '\0';
	(void)build_topics();

#if defined(CONFIG_RADAR_CARE_MQTT_TLS)
	(void)tls_credentials_setup();
#endif
}

void care_mqtt_set_cmd_handler(care_cmd_handler_t handler)
{
	cmd_handler = handler;
}

int care_mqtt_publish(const char *subtopic, const char *payload, bool retain, int qos)
{
	char topic[TOPIC_MAX];
	int ret;

	if (!connected) {
		return -ENOTCONN;
	}

	ret = snprintk(topic, sizeof(topic), "%s/%s", base_topic, subtopic);
	if (ret < 0 || ret >= (int)sizeof(topic)) {
		return -ENAMETOOLONG;
	}

	struct mqtt_publish_param param = {
		.message.topic.topic.utf8 = (uint8_t *)topic,
		.message.topic.topic.size = strlen(topic),
		.message.topic.qos = qos,
		.message.payload.data = (uint8_t *)payload,
		.message.payload.len = strlen(payload),
		.message_id = sys_rand16_get(),
		.retain_flag = retain ? 1U : 0U,
	};

	k_mutex_lock(&mqtt_lock, K_FOREVER);
	ret = mqtt_publish(&client_ctx, &param);
	if (ret == 0) {
		(void)mqtt_live(&client_ctx);
	}
	k_mutex_unlock(&mqtt_lock);

	return ret;
}

static int subscribe_cmd(void)
{
	struct mqtt_topic topic = {
		.topic = { .utf8 = (uint8_t *)cmd_topic, .size = strlen(cmd_topic) },
		.qos = MQTT_QOS_1_AT_LEAST_ONCE,
	};
	const struct mqtt_subscription_list sub = {
		.list = &topic,
		.list_count = 1,
		.message_id = 1U,
	};

	return mqtt_subscribe(&client_ctx, &sub);
}

int care_mqtt_process(int timeout_ms)
{
	int rc;

	k_mutex_lock(&mqtt_lock, K_FOREVER);
	if (wait_on_socket(timeout_ms) > 0) {
		rc = mqtt_input(&client_ctx);
		if (rc < 0) {
			goto out;
		}
	}
	rc = mqtt_live(&client_ctx);
	if (rc == -EAGAIN) {
		rc = 0;
	}
out:
	k_mutex_unlock(&mqtt_lock);
	return rc;
}

int care_mqtt_connect(void)
{
	int ret;

	connected = false;

	ret = broker_addr_setup();
	if (ret != 0) {
		return ret;
	}

	client_init(&client_ctx);

	ret = mqtt_connect(&client_ctx);
	if (ret != 0) {
		LOG_WRN("mqtt_connect: %d", ret);
		return ret;
	}

	fds[0].fd = transport_socket(&client_ctx);
	fds[0].events = POLLIN;
	nfds = 1;

	/* Pump until CONNACK (or failure). */
	for (int i = 0; i < 40 && !connected; i++) {
		ret = care_mqtt_process(200);
		if (ret < 0) {
			(void)mqtt_abort(&client_ctx);
			nfds = 0;
			return ret;
		}
	}

	if (!connected) {
		(void)mqtt_abort(&client_ctx);
		nfds = 0;
		return -ETIMEDOUT;
	}

	(void)subscribe_cmd();
	(void)care_mqtt_publish("status", "{\"online\":true}", true,
				MQTT_QOS_1_AT_LEAST_ONCE);

	LOG_INF("Telemetry up: %s (broker %s:%d)", base_topic,
		CONFIG_RADAR_CARE_BROKER_HOSTNAME, CONFIG_RADAR_CARE_BROKER_PORT);

	return 0;
}

bool care_mqtt_is_connected(void)
{
	return connected;
}

void care_mqtt_disconnect(void)
{
	(void)mqtt_disconnect(&client_ctx, NULL);
	nfds = 0;
	connected = false;
}
