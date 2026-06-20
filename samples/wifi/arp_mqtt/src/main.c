/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/conn_mgr_connectivity.h>
#include <zephyr/net/conn_mgr_monitor.h>
#include <zephyr/net/icmp.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>
#include <zephyr/random/random.h>
#include <zephyr/posix/arpa/inet.h>
#include <zephyr/posix/netdb.h>
#include <zephyr/posix/poll.h>
#include <zephyr/posix/sys/socket.h>
#include <zephyr/shell/shell.h>

#include <hw_id.h>

#include "net_sample_common.h"

LOG_MODULE_REGISTER(arp_mqtt, CONFIG_LOG_DEFAULT_LEVEL);

#define MQTT_BUFFER_SIZE CONFIG_ARP_MQTT_APP_BUFFER_SIZE
#define MQTT_SUB_TOPIC   CONFIG_ARP_MQTT_SUB_TOPIC
#define MQTT_PUB_PREFIX  CONFIG_ARP_MQTT_PUB_TOPIC_PREFIX

/* Periodic RTT report: ping the broker N times and publish the delays. */
#define RTT_TOPIC          "nrf/rtt"
#define RTT_PING_COUNT     3
#define RTT_PING_INTERVAL  K_MSEC(1000)
#define RTT_PING_TIMEOUT   K_MSEC(1000)
/* Each entry is at most "65535ms," -> 8 chars; allow margin for "Nan" too. */
#define RTT_PAYLOAD_SIZE   (RTT_PING_COUNT * 10)

static uint8_t rx_buffer[MQTT_BUFFER_SIZE];
static uint8_t tx_buffer[MQTT_BUFFER_SIZE];

static struct mqtt_client client_ctx;
static struct sockaddr_storage broker;
static struct pollfd fds[1];
static int nfds;
static volatile bool mqtt_got_connack;

/* "nrf_" + 4 hex digits + NUL */
static char mqtt_client_id[9];

static K_MUTEX_DEFINE(mqtt_lock);

/* ICMP echo (ping) state for the periodic RTT report. */
static struct net_icmp_ctx ping_icmp_ctx;
static K_SEM_DEFINE(ping_reply_sem, 0, 1);
static uint16_t ping_identifier;
static uint16_t ping_active_sequence;

static int mqtt_client_id_set(void)
{
	char hw[HW_ID_LEN];
	int ret;

	ret = hw_id_get(hw, sizeof(hw));
	if (ret != 0) {
		LOG_ERR("hw_id_get failed: %d", ret);
		return ret;
	}

	if (strlen(hw) < 12) {
		LOG_ERR("Unexpected HW ID length");
		return -EINVAL;
	}

	ret = snprintk(mqtt_client_id, sizeof(mqtt_client_id), "nrf_%s", &hw[8]);
	if (ret < 0 || ret >= (int)sizeof(mqtt_client_id)) {
		return -ENOSPC;
	}

	return 0;
}

static void broker_addr_str(char *buf, size_t len)
{
	const void *addr;
	sa_family_t family;

	if (broker.ss_family == AF_INET) {
		family = AF_INET;
		addr = &((struct sockaddr_in *)&broker)->sin_addr;
	} else if (broker.ss_family == AF_INET6) {
		family = AF_INET6;
		addr = &((struct sockaddr_in6 *)&broker)->sin6_addr;
	} else {
		(void)snprintk(buf, len, "(unknown)");
		return;
	}

	if (inet_ntop(family, addr, buf, len) == NULL) {
		(void)snprintk(buf, len, "(invalid)");
	}
}

static bool broker_addr_family_supported(sa_family_t family)
{
	if (family == AF_INET) {
		return IS_ENABLED(CONFIG_NET_IPV4);
	}

	if (family == AF_INET6) {
		return IS_ENABLED(CONFIG_NET_IPV6);
	}

	return false;
}

#if defined(CONFIG_NET_IPV4) && defined(CONFIG_NET_IPV6)
static bool broker_addr_family_preferred(sa_family_t family)
{
	if (IS_ENABLED(CONFIG_ARP_MQTT_BROKER_PREFER_IPV6)) {
		return family == AF_INET6;
	}

	return family == AF_INET;
}
#endif

static int broker_addr_from_ai(const struct zsock_addrinfo *ai)
{
	if (!broker_addr_family_supported(ai->ai_addr->sa_family)) {
		return -EINVAL;
	}

	if (ai->ai_addrlen > sizeof(broker)) {
		return -EINVAL;
	}

	(void)memset(&broker, 0, sizeof(broker));
	(void)memcpy(&broker, ai->ai_addr, ai->ai_addrlen);
	return 0;
}

static void prepare_fds(struct mqtt_client *client)
{
	fds[0].fd = client->transport.tcp.sock;
	fds[0].events = POLLIN;
	nfds = 1;
}

static void clear_fds(void)
{
	nfds = 0;
}

static int handle_incoming_publish(struct mqtt_client *client,
				   const struct mqtt_publish_param *pub)
{
	size_t payload_len = pub->message.payload.len;
	size_t received = 0;
	char topic[128];
	char payload[MQTT_BUFFER_SIZE];
	size_t topic_len = MIN(pub->message.topic.topic.size, sizeof(topic) - 1);

	(void)memcpy(topic, pub->message.topic.topic.utf8, topic_len);
	topic[topic_len] = '\0';

	if (payload_len >= sizeof(payload)) {
		LOG_WRN("MQTT RX topic=%s payload too large (%zu bytes)", topic, payload_len);
		return -ENOMEM;
	}

	while (received < payload_len) {
		int ret = mqtt_read_publish_payload_blocking(client,
							   &payload[received],
							   payload_len - received);

		if (ret < 0) {
			return ret;
		}

		received += ret;
	}

	payload[received] = '\0';
	LOG_INF("MQTT RX topic=%s payload=%s", topic, payload);

	if (pub->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
		struct mqtt_puback_param puback = {
			.message_id = pub->message_id,
		};

		(void)mqtt_publish_qos1_ack(client, &puback);
	}

	return 0;
}

static void mqtt_evt_handler(struct mqtt_client *const client, const struct mqtt_evt *evt)
{
	ARG_UNUSED(client);

	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		if (evt->result != 0) {
			LOG_ERR("MQTT connect failed: %d", evt->result);
			mqtt_got_connack = false;
			break;
		}
		mqtt_got_connack = true;
		{
			char addr[NET_IPV6_ADDR_LEN];

			broker_addr_str(addr, sizeof(addr));
			LOG_INF("MQTT session up (broker [%s]:%d, subscribe %s)", addr,
				CONFIG_ARP_MQTT_BROKER_PORT, MQTT_SUB_TOPIC);
		}
		break;
	case MQTT_EVT_PUBLISH:
		(void)handle_incoming_publish(client, &evt->param.publish);
		break;
	case MQTT_EVT_SUBACK:
		if (evt->result != 0) {
			LOG_ERR("MQTT subscribe failed: %d", evt->result);
		} else {
			LOG_INF("MQTT subscribed to %s", MQTT_SUB_TOPIC);
		}
		break;
	case MQTT_EVT_DISCONNECT:
		LOG_INF("MQTT disconnected (%d)", evt->result);
		mqtt_got_connack = false;
		clear_fds();
		break;
	default:
		break;
	}
}

static int broker_addr_setup(void)
{
	struct zsock_addrinfo hints = {
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	struct zsock_addrinfo *res;
	struct zsock_addrinfo *ai;
	char portstr[8];
	int err;

	(void)memset(&broker, 0, sizeof(broker));

	if (IS_ENABLED(CONFIG_NET_IPV4)) {
		struct sockaddr_in *b4 = (struct sockaddr_in *)&broker;

		b4->sin_family = AF_INET;
		b4->sin_port = htons(CONFIG_ARP_MQTT_BROKER_PORT);
		if (inet_pton(AF_INET, CONFIG_ARP_MQTT_BROKER_HOSTNAME, &b4->sin_addr) == 1) {
			return 0;
		}
	}

	if (IS_ENABLED(CONFIG_NET_IPV6)) {
		struct sockaddr_in6 *b6 = (struct sockaddr_in6 *)&broker;

		b6->sin6_family = AF_INET6;
		b6->sin6_port = htons(CONFIG_ARP_MQTT_BROKER_PORT);
		if (inet_pton(AF_INET6, CONFIG_ARP_MQTT_BROKER_HOSTNAME, &b6->sin6_addr) == 1) {
			return 0;
		}
	}

	(void)snprintk(portstr, sizeof(portstr), "%d", CONFIG_ARP_MQTT_BROKER_PORT);

#if defined(CONFIG_NET_IPV4) && defined(CONFIG_NET_IPV6)
	hints.ai_family = AF_UNSPEC;
#elif defined(CONFIG_NET_IPV6)
	hints.ai_family = AF_INET6;
#else
	hints.ai_family = AF_INET;
#endif

	err = getaddrinfo(CONFIG_ARP_MQTT_BROKER_HOSTNAME, portstr, &hints, &res);
	if (err != 0 || res == NULL) {
		LOG_ERR("getaddrinfo(%s): %d", CONFIG_ARP_MQTT_BROKER_HOSTNAME, err);
		return -EINVAL;
	}

#if defined(CONFIG_NET_IPV4) && defined(CONFIG_NET_IPV6)
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		if (broker_addr_family_preferred(ai->ai_addr->sa_family) &&
		    broker_addr_from_ai(ai) == 0) {
			freeaddrinfo(res);
			return 0;
		}
	}
#endif

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		if (broker_addr_from_ai(ai) == 0) {
			freeaddrinfo(res);
			return 0;
		}
	}

	freeaddrinfo(res);
	LOG_ERR("No supported address for broker %s", CONFIG_ARP_MQTT_BROKER_HOSTNAME);
	return -EINVAL;
}

static void client_init(struct mqtt_client *client)
{
	mqtt_client_init(client);

	if (mqtt_client_id_set() != 0) {
		(void)strncpy(mqtt_client_id, "nrf_0000", sizeof(mqtt_client_id));
		mqtt_client_id[sizeof(mqtt_client_id) - 1] = '\0';
	}

	LOG_INF("MQTT client ID %s", mqtt_client_id);

	client->broker = &broker;
	client->evt_cb = mqtt_evt_handler;
	client->client_id.utf8 = (uint8_t *)mqtt_client_id;
	client->client_id.size = strlen(mqtt_client_id);
	client->password = NULL;
	client->user_name = NULL;
	client->protocol_version = MQTT_VERSION_3_1_1;

	client->rx_buf = rx_buffer;
	client->rx_buf_size = sizeof(rx_buffer);
	client->tx_buf = tx_buffer;
	client->tx_buf_size = sizeof(tx_buffer);

	client->transport.type = MQTT_TRANSPORT_NON_SECURE;
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

static int mqtt_process(struct mqtt_client *client, int timeout_ms)
{
	int64_t deadline = k_uptime_get() + timeout_ms;

	while (k_uptime_get() < deadline) {
		int slice = (int)(deadline - k_uptime_get());

		if (slice > 400) {
			slice = 400;
		} else if (slice < 0) {
			slice = 0;
		}

		if (wait_on_socket(slice) > 0) {
			int rc = mqtt_input(client);

			if (rc < 0) {
				return rc;
			}
		}

		int rc = mqtt_live(client);

		if (rc != 0 && rc != -EAGAIN) {
			return rc;
		}
		if (rc == 0) {
			rc = mqtt_input(client);
			if (rc < 0) {
				return rc;
			}
		}
	}

	return 0;
}

static int mqtt_subscribe_topics(struct mqtt_client *client)
{
	struct mqtt_topic topic = {
		.topic = {
			.utf8 = (uint8_t *)MQTT_SUB_TOPIC,
			.size = strlen(MQTT_SUB_TOPIC),
		},
		.qos = MQTT_QOS_0_AT_MOST_ONCE,
	};
	const struct mqtt_subscription_list sub_list = {
		.list = &topic,
		.list_count = 1,
		.message_id = 1U,
	};

	return mqtt_subscribe(client, &sub_list);
}

static int try_mqtt_connect(struct mqtt_client *client)
{
	int ret;
	int attempt = 0;

	while (attempt++ < 30) {
		mqtt_got_connack = false;

		if (broker_addr_setup() != 0) {
			k_sleep(K_SECONDS(2));
			continue;
		}

		client_init(client);

		ret = mqtt_connect(client);
		if (ret != 0) {
			LOG_WRN("mqtt_connect failed: %d", ret);
			k_sleep(K_SECONDS(2));
			continue;
		}

		prepare_fds(client);

		ret = mqtt_process(client, 15000);
		if (ret < 0) {
			LOG_ERR("mqtt_process during connect: %d", ret);
			(void)mqtt_abort(client);
			clear_fds();
			k_sleep(K_SECONDS(2));
			continue;
		}

		if (!mqtt_got_connack) {
			LOG_WRN("No CONNACK, retrying");
			(void)mqtt_abort(client);
			clear_fds();
			k_sleep(K_SECONDS(2));
			continue;
		}

		ret = mqtt_subscribe_topics(client);
		if (ret != 0) {
			LOG_ERR("mqtt_subscribe failed: %d", ret);
			(void)mqtt_abort(client);
			clear_fds();
			k_sleep(K_SECONDS(2));
			continue;
		}

		ret = mqtt_process(client, 5000);
		if (ret < 0) {
			LOG_ERR("mqtt_process during subscribe: %d", ret);
			(void)mqtt_abort(client);
			clear_fds();
			k_sleep(K_SECONDS(2));
			continue;
		}

		return 0;
	}

	return -ETIMEDOUT;
}

static int mqtt_publish_payload(struct mqtt_client *client, const char *topic,
				const char *payload)
{
	static uint16_t message_id;
	int ret;
	size_t payload_len = strlen(payload);

	struct mqtt_publish_param param = {
		.message.topic.topic.utf8 = (uint8_t *)topic,
		.message.topic.topic.size = strlen(topic),
		.message.topic.qos = MQTT_QOS_0_AT_MOST_ONCE,
		.message.payload.data = (uint8_t *)payload,
		.message.payload.len = payload_len,
		.message_id = message_id++,
		.dup_flag = 0U,
		.retain_flag = 0U,
	};

	k_mutex_lock(&mqtt_lock, K_FOREVER);
	ret = mqtt_publish(client, &param);
	if (ret == 0) {
		(void)mqtt_live(client);
	}
	k_mutex_unlock(&mqtt_lock);

	return ret;
}

static enum net_verdict ping_reply_handler(struct net_icmp_ctx *ctx, struct net_pkt *pkt,
					   struct net_icmp_ip_hdr *ip_hdr,
					   struct net_icmp_hdr *icmp_hdr, void *user_data)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(pkt);
	ARG_UNUSED(ip_hdr);
	ARG_UNUSED(icmp_hdr);
	ARG_UNUSED(user_data);

	/* Only one echo request is outstanding at a time, so any matching-family
	 * reply that arrives while we are waiting is the one we sent.
	 */
	k_sem_give(&ping_reply_sem);

	return NET_OK;
}

/* Send one echo request to the broker and return the round-trip time in
 * milliseconds, or -1 on send error or timeout.
 */
static int ping_broker_once(uint16_t sequence)
{
	struct net_icmp_ping_params params = {
		.identifier = ping_identifier,
		.sequence = sequence,
		.tc_tos = 0,
		.priority = -1,
		.data = NULL,
		.data_size = 4,
	};
	int64_t start;
	int ret;

	k_sem_reset(&ping_reply_sem);
	ping_active_sequence = sequence;

	start = k_uptime_get();

	ret = net_icmp_send_echo_request(&ping_icmp_ctx, NULL, (struct net_sockaddr *)&broker,
					 &params, NULL);
	if (ret < 0) {
		LOG_WRN("ping send (seq %u) failed: %d", sequence, ret);
		return -1;
	}

	if (k_sem_take(&ping_reply_sem, RTT_PING_TIMEOUT) != 0) {
		LOG_WRN("ping timeout (seq %u)", sequence);
		return -1;
	}

	return (int)(k_uptime_get() - start);
}

/* Ping the broker RTT_PING_COUNT times and build a comma-separated delay
 * string such as "5ms,102ms,4ms". Failed pings are reported as "Nan".
 */
static void build_rtt_payload(char *buf, size_t buf_len)
{
	bool icmp_ready;
	size_t off = 0;
	int ret;

	buf[0] = '\0';

	ret = net_icmp_init_ctx(&ping_icmp_ctx, broker.ss_family,
				(broker.ss_family == AF_INET6) ? NET_ICMPV6_ECHO_REPLY
							       : NET_ICMPV4_ECHO_REPLY,
				0, ping_reply_handler);
	icmp_ready = (ret == 0);
	if (!icmp_ready) {
		LOG_WRN("net_icmp_init_ctx failed: %d (reporting Nan)", ret);
	}

	ping_identifier = sys_rand16_get();

	for (uint16_t i = 0; i < RTT_PING_COUNT; i++) {
		const char *sep = (i == 0) ? "" : ",";
		int rtt = icmp_ready ? ping_broker_once(i + 1) : -1;

		if (rtt >= 0) {
			off += snprintk(&buf[off], buf_len - off, "%s%dms", sep, rtt);
		} else {
			off += snprintk(&buf[off], buf_len - off, "%sNan", sep);
		}

		if (off >= buf_len) {
			LOG_WRN("RTT payload truncated");
			break;
		}

		if (i < RTT_PING_COUNT - 1) {
			k_sleep(RTT_PING_INTERVAL);
		}
	}

	if (icmp_ready) {
		(void)net_icmp_cleanup_ctx(&ping_icmp_ctx);
	}
}

static void rtt_report_thread(void)
{
	char payload[RTT_PAYLOAD_SIZE];

	for (;;) {
		k_sleep(K_SECONDS(CONFIG_ARP_MQTT_RTT_PERIOD_SECONDS));

		if (!mqtt_got_connack) {
			LOG_WRN("RTT report skipped: MQTT not connected");
			continue;
		}

		build_rtt_payload(payload, sizeof(payload));

		int ret = mqtt_publish_payload(&client_ctx, RTT_TOPIC, payload);

		if (ret != 0) {
			LOG_WRN("RTT publish to %s failed: %d", RTT_TOPIC, ret);
		} else {
			LOG_INF("Published RTT to %s: %s", RTT_TOPIC, payload);
		}
	}
}

K_THREAD_DEFINE(rtt_report_tid, 2048, rtt_report_thread, NULL, NULL, NULL,
		K_LOWEST_APPLICATION_THREAD_PRIO, 0, 0);

static int cmd_mqtt_pub(const struct shell *sh, size_t argc, char **argv)
{
	char topic[96];
	int ret;

	if (argc != 3) {
		shell_error(sh, "Usage: mqtt_pub <topic> <value>");
		return -EINVAL;
	}

	if (strchr(argv[1], '/') != NULL) {
		shell_error(sh, "Topic must not contain '/'");
		return -EINVAL;
	}

	if (strlen(argv[2]) >= MQTT_BUFFER_SIZE) {
		shell_error(sh, "Value too long (max %d)", MQTT_BUFFER_SIZE - 1);
		return -EINVAL;
	}

	if (!mqtt_got_connack) {
		shell_error(sh, "MQTT not connected");
		return -ENOTCONN;
	}

	ret = snprintk(topic, sizeof(topic), MQTT_PUB_PREFIX "%s", argv[1]);
	if (ret < 0 || ret >= (int)sizeof(topic)) {
		shell_error(sh, "Topic too long");
		return -ENAMETOOLONG;
	}

	ret = mqtt_publish_payload(&client_ctx, topic, argv[2]);
	if (ret != 0) {
		shell_error(sh, "mqtt_publish failed: %d", ret);
		return ret;
	}

	return 0;
}

SHELL_CMD_REGISTER(mqtt_pub, NULL,
		 "Publish <value> to " MQTT_PUB_PREFIX "<topic>: mqtt_pub <topic> <value>",
		 cmd_mqtt_pub);

int main(void)
{
	int err;

	LOG_INF("ARP MQTT (Wi-Fi) client starting");

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

	if (IS_ENABLED(CONFIG_BOARD_NATIVE_SIM)) {
		conn_mgr_mon_resend_status();
	}

	wait_for_network();

	for (;;) {
		err = try_mqtt_connect(&client_ctx);
		if (err != 0) {
			LOG_ERR("Broker connect failed, retry in 10 s");
			k_sleep(K_SECONDS(10));
			continue;
		}

		while (mqtt_got_connack) {
			k_mutex_lock(&mqtt_lock, K_FOREVER);
			err = mqtt_process(&client_ctx, 1000);
			k_mutex_unlock(&mqtt_lock);
			if (err < 0) {
				LOG_ERR("mqtt_process: %d", err);
				break;
			}
		}

		(void)mqtt_disconnect(&client_ctx, NULL);
		clear_fds();
		k_sleep(K_SECONDS(3));
	}
}
