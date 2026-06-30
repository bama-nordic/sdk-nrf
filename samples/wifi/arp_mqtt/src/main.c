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
#include <zephyr/net/net_event.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi_mgmt.h>
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
#if defined(CONFIG_ARP_MQTT_ENABLE_SUB)
#define MQTT_SUB_TOPIC   CONFIG_ARP_MQTT_SUB_TOPIC
#endif
#define MQTT_PUB_PREFIX  CONFIG_ARP_MQTT_PUB_TOPIC_PREFIX

#if defined(CONFIG_ARP_MQTT_PERIODIC_PUB)
/* Periodic RTT report: ping the broker N times and publish the delays. */
#define RTT_TOPIC          "sensor"
#define RTT_PING_COUNT     3
#define RTT_PING_INTERVAL  K_MSEC(1000)
#define RTT_PING_TIMEOUT   K_MSEC(1000)
/* Each entry is at most "65535ms," -> 8 chars; allow margin for "Nan" too. */
#define RTT_PAYLOAD_SIZE   (RTT_PING_COUNT * 10)
#endif /* CONFIG_ARP_MQTT_PERIODIC_PUB */

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

/* Per-family L4 connectivity, tracked so the broker connect is only attempted
 * once the relevant IP family has a usable address. With dual-stack enabled the
 * generic NET_EVENT_L4_CONNECTED fires as soon as *either* family is up (IPv6
 * link-local/RA is typically ready well before IPv4 DHCP), which would make the
 * first connect attempts to an IPv4 broker fail with -EINVAL.
 */
#define L4_FAMILY_EVENT_MASK                                                    \
	(NET_EVENT_L4_IPV4_CONNECTED | NET_EVENT_L4_IPV4_DISCONNECTED |         \
	 NET_EVENT_L4_IPV6_CONNECTED | NET_EVENT_L4_IPV6_DISCONNECTED)

static struct net_mgmt_event_callback l4_family_cb;
static atomic_t ipv4_connected;
static atomic_t ipv6_connected;
static K_SEM_DEFINE(l4_family_changed, 0, 1);

#if defined(CONFIG_ARP_MQTT_PERIODIC_PUB)
/* ICMP echo (ping) state for the periodic RTT report. */
static struct net_icmp_ctx ping_icmp_ctx;
static K_SEM_DEFINE(ping_reply_sem, 0, 1);
static uint16_t ping_identifier;
static uint16_t ping_active_sequence;

/* Released by main() once network bring-up has started. Keeps the periodic
 * publisher idle during the startup delay (e.g. random_sleep()) instead of
 * spinning and logging "MQTT not connected" before main() has run.
 */
static K_SEM_DEFINE(app_ready, 0, 1);
#endif /* CONFIG_ARP_MQTT_PERIODIC_PUB */

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

#if defined(CONFIG_ARP_MQTT_ENABLE_SUB)
static int handle_incoming_publish(struct mqtt_client *client,
				   const struct mqtt_publish_param *pub)
{
	/* Called only from the single mqtt_process() context (main thread), so
	 * these scratch buffers are static to keep the main stack small.
	 */
	static char topic[128];
	static char payload[MQTT_BUFFER_SIZE];
	size_t payload_len = pub->message.payload.len;
	size_t topic_len = MIN(pub->message.topic.topic.size, sizeof(topic) - 1);
	size_t remaining = payload_len;
	size_t stored = 0;

	(void)memcpy(topic, pub->message.topic.topic.utf8, topic_len);
	topic[topic_len] = '\0';

	/* The payload must always be drained from the socket, even when it does
	 * not fit our buffer. Any bytes left unread keep remaining_payload > 0
	 * in the MQTT client, so the next mqtt_input() returns -EBUSY and the
	 * connection is dropped. Store what fits and discard the rest.
	 */
	while (remaining > 0) {
		uint8_t chunk[64];
		size_t want = MIN(remaining, sizeof(chunk));
		int ret = mqtt_read_publish_payload_blocking(client, chunk, want);

		if (ret < 0) {
			return ret;
		}

		if (stored < sizeof(payload) - 1) {
			size_t copy = MIN((size_t)ret, sizeof(payload) - 1 - stored);

			(void)memcpy(&payload[stored], chunk, copy);
			stored += copy;
		}

		remaining -= ret;
	}

	payload[stored] = '\0';

	if (stored < payload_len) {
		LOG_WRN("MQTT RX topic=%s payload truncated (%zu of %zu bytes)", topic, stored,
			payload_len);
	}
	LOG_INF("MQTT RX topic=%s payload=%s", topic, payload);

	if (pub->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
		struct mqtt_puback_param puback = {
			.message_id = pub->message_id,
		};

		(void)mqtt_publish_qos1_ack(client, &puback);
	}

	return 0;
}
#else /* CONFIG_ARP_MQTT_ENABLE_SUB */
/* Publish-only build. We never subscribe and connect with a clean session, so
 * the broker should not deliver anything. Still, an in-flight or retained
 * PUBLISH could arrive; drain and discard it so remaining_payload returns to 0
 * and the connection is not dropped with -EBUSY. The message is not acted on.
 */
static int handle_incoming_publish(struct mqtt_client *client,
				   const struct mqtt_publish_param *pub)
{
	size_t remaining = pub->message.payload.len;

	while (remaining > 0) {
		uint8_t chunk[64];
		size_t want = MIN(remaining, sizeof(chunk));
		int ret = mqtt_read_publish_payload_blocking(client, chunk, want);

		if (ret < 0) {
			return ret;
		}

		remaining -= ret;
	}

	LOG_DBG("Dropped unexpected MQTT publish (%zu bytes)", pub->message.payload.len);

	if (pub->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
		struct mqtt_puback_param puback = {
			.message_id = pub->message_id,
		};

		(void)mqtt_publish_qos1_ack(client, &puback);
	}

	return 0;
}
#endif /* CONFIG_ARP_MQTT_ENABLE_SUB */

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
#if defined(CONFIG_ARP_MQTT_ENABLE_SUB)
			LOG_INF("MQTT session up (broker [%s]:%d, subscribe %s)", addr,
				CONFIG_ARP_MQTT_BROKER_PORT, MQTT_SUB_TOPIC);
#else
			LOG_INF("MQTT session up (broker [%s]:%d, publish-only)", addr,
				CONFIG_ARP_MQTT_BROKER_PORT);
#endif
		}
		break;
	case MQTT_EVT_PUBLISH:
		(void)handle_incoming_publish(client, &evt->param.publish);
		break;
#if defined(CONFIG_ARP_MQTT_ENABLE_SUB)
	case MQTT_EVT_SUBACK:
		if (evt->result != 0) {
			LOG_ERR("MQTT subscribe failed: %d", evt->result);
		} else {
			LOG_INF("MQTT subscribed to %s", MQTT_SUB_TOPIC);
		}
		break;
#endif /* CONFIG_ARP_MQTT_ENABLE_SUB */
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

#if !defined(CONFIG_ARP_MQTT_ENABLE_SUB)
	/* Publish-only build: start a clean session so the broker discards any
	 * subscription left over from a previous (persistent) session under the
	 * same client ID. This guarantees the broker delivers nothing to this
	 * device, i.e. it does not respond to any publisher.
	 */
	client->clean_session = 1U;
#endif

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

#if defined(CONFIG_ARP_MQTT_ENABLE_SUB)
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
#endif /* CONFIG_ARP_MQTT_ENABLE_SUB */

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

static bool broker_family_connected(sa_family_t family)
{
	if (family == AF_INET) {
		return atomic_get(&ipv4_connected) != 0;
	}

	if (family == AF_INET6) {
		return atomic_get(&ipv6_connected) != 0;
	}

	return false;
}

/* Block until the broker's IP family has L4 connectivity, so the first connect
 * does not race the address assignment. Returns -ETIMEDOUT if it does not come
 * up in time; the caller then falls through and lets the connect retry.
 */
static int wait_for_broker_family(sa_family_t family)
{
	int64_t deadline = k_uptime_get() + 30000;

	while (!broker_family_connected(family)) {
		if (k_uptime_get() >= deadline) {
			return -ETIMEDOUT;
		}

		(void)k_sem_take(&l4_family_changed, K_MSEC(500));
	}

	return 0;
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

		if (wait_for_broker_family(broker.ss_family) != 0) {
			LOG_WRN("No L4 connectivity for broker family yet");
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

#if defined(CONFIG_ARP_MQTT_ENABLE_SUB)
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
#endif /* CONFIG_ARP_MQTT_ENABLE_SUB */

		return 0;
	}

	return -ETIMEDOUT;
}

/* Device MAC as "aa:bb:cc:dd:ee:ff" (lower-case) + NUL. */
static char mac_str[18];

static const char *mac_str_get(void)
{
	struct net_if *iface;
	struct net_linkaddr *ll;

	if (mac_str[0] != '\0') {
		return mac_str;
	}

	iface = net_if_get_first_wifi();
	if (iface == NULL) {
		iface = net_if_get_default();
	}

	ll = (iface != NULL) ? net_if_get_link_addr(iface) : NULL;

	if (ll != NULL && ll->len >= 6U) {
		const uint8_t *m = ll->addr;

		/* Cache only once a real MAC is available. */
		(void)snprintk(mac_str, sizeof(mac_str),
			       "%02x:%02x:%02x:%02x:%02x:%02x",
			       m[0], m[1], m[2], m[3], m[4], m[5]);
		return mac_str;
	}

	return "00:00:00:00:00:00";
}

static int mqtt_publish_payload(struct mqtt_client *client, const char *topic,
				const char *payload)
{
	static uint16_t message_id;
	/* "<mac> <payload>"; serialized by mqtt_lock, so a static buffer keeps
	 * it off the (small) caller stacks even for a full-size payload.
	 */
	static char pub_buf[MQTT_BUFFER_SIZE + 16];
	size_t payload_len;
	int written;
	int ret;

	k_mutex_lock(&mqtt_lock, K_FOREVER);

	written = snprintk(pub_buf, sizeof(pub_buf), "%s %s", mac_str_get(), payload);
	payload_len = (written > 0 && (size_t)written < sizeof(pub_buf))
			      ? (size_t)written
			      : (sizeof(pub_buf) - 1U);

	struct mqtt_publish_param param = {
		.message.topic.topic.utf8 = (uint8_t *)topic,
		.message.topic.topic.size = strlen(topic),
		.message.topic.qos = MQTT_QOS_0_AT_MOST_ONCE,
		.message.payload.data = (uint8_t *)pub_buf,
		.message.payload.len = payload_len,
		.message_id = message_id++,
		.dup_flag = 0U,
		.retain_flag = 0U,
	};

	ret = mqtt_publish(client, &param);
	if (ret == 0) {
		(void)mqtt_live(client);
		LOG_INF("MQTT TX topic=%s payload=%s", topic, pub_buf);
	}
	k_mutex_unlock(&mqtt_lock);

	return ret;
}

#if defined(CONFIG_ARP_MQTT_PERIODIC_PUB)
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

	/* Block until main() has started network bring-up, so this thread does
	 * not run during the pre-main startup delay.
	 */
	k_sem_take(&app_ready, K_FOREVER);

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
		}
		/* The actual transmitted payload (with MAC) is logged by
		 * mqtt_publish_payload() as "MQTT TX ...".
		 */
	}
}

K_THREAD_DEFINE(rtt_report_tid, 2048, rtt_report_thread, NULL, NULL, NULL,
		K_LOWEST_APPLICATION_THREAD_PRIO, 0, 0);
#endif /* CONFIG_ARP_MQTT_PERIODIC_PUB */

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

#if defined(CONFIG_ARP_MQTT_WIFI_LISTEN_INTERVAL)
static int wifi_set_listen_interval(void)
{
	struct net_if *iface = net_if_get_first_wifi();
	struct wifi_ps_params li_params = {
		.type = WIFI_PS_PARAM_LISTEN_INTERVAL,
		.listen_interval = CONFIG_ARP_MQTT_WIFI_LISTEN_INTERVAL_VALUE,
	};
	struct wifi_ps_params wakeup_params = {
		.type = WIFI_PS_PARAM_WAKEUP_MODE,
		.wakeup_mode = WIFI_PS_WAKEUP_MODE_LISTEN_INTERVAL,
	};
	int err;

	if (iface == NULL) {
		LOG_ERR("No Wi-Fi interface found");
		return -ENODEV;
	}

	err = net_mgmt(NET_REQUEST_WIFI_PS, iface, &li_params, sizeof(li_params));
	if (err) {
		LOG_ERR("Failed to set listen interval (%u): %d (reason %d)",
			li_params.listen_interval, err, li_params.fail_reason);
		return err;
	}

	err = net_mgmt(NET_REQUEST_WIFI_PS, iface, &wakeup_params, sizeof(wakeup_params));
	if (err) {
		LOG_ERR("Failed to set listen interval wakeup mode: %d (reason %d)",
			err, wakeup_params.fail_reason);
		return err;
	}

	LOG_INF("Wi-Fi power save: listen interval wakeup, %u beacon intervals",
		li_params.listen_interval);

	return 0;
}
#endif /* CONFIG_ARP_MQTT_WIFI_LISTEN_INTERVAL */

void random_sleep(void)
{
    /* Random value between 1 and 50 seconds */
    uint32_t sleep_sec = (sys_rand32_get() % 50) + 1;

    printk("Sleeping for %u seconds...\n", sleep_sec);

    k_sleep(K_SECONDS(sleep_sec));
}

int main(void)
{
	int err;

	random_sleep();

	LOG_INF("ARP MQTT (Wi-Fi) client starting");

	net_mgmt_init_event_callback(&l4_family_cb, l4_family_event_handler,
				     L4_FAMILY_EVENT_MASK);
	net_mgmt_add_event_callback(&l4_family_cb);

	err = conn_mgr_all_if_up(true);
	if (err) {
		LOG_ERR("conn_mgr_all_if_up: %d", err);
		return err;
	}

#if defined(CONFIG_ARP_MQTT_WIFI_LISTEN_INTERVAL)
	/* The listen interval is part of the association request, so the Wi-Fi
	 * stack only accepts it while the station is not associated. Configure
	 * it after the interface is up but before initiating the connection.
	 */
	(void)wifi_set_listen_interval();
#endif

	err = conn_mgr_all_if_connect(true);
	if (err) {
		LOG_ERR("conn_mgr_all_if_connect: %d", err);
		return err;
	}

	if (IS_ENABLED(CONFIG_BOARD_NATIVE_SIM)) {
		conn_mgr_mon_resend_status();
	}

	wait_for_network();

#if defined(CONFIG_ARP_MQTT_PERIODIC_PUB)
	/* Network is up; allow the periodic publisher to start. */
	k_sem_give(&app_ready);
#endif

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
