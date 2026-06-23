/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Minimal hand-rolled JSON serialization for care events. Kept dependency-free
 * and bounded; payloads are small and flat.
 */

#include <stdio.h>

#include "care.h"

static const char *fall_state_str(enum care_fall_state s)
{
	switch (s) {
	case CARE_FALL_SUSPECTED:
		return "suspected";
	case CARE_FALL_CONFIRMED:
		return "confirmed";
	case CARE_FALL_NONE:
	default:
		return "none";
	}
}

static int waveform_to_json(const struct care_event *evt, char *buf, size_t buf_size)
{
	const struct care_waveform *w = &evt->waveform;
	int off;

	off = snprintf(buf, buf_size, "{\"ts_ms\":%u,\"fs\":%u,\"samples\":[",
		       evt->uptime_ms, w->fs_hz);
	if (off < 0 || (size_t)off >= buf_size) {
		return -1;
	}

	for (uint8_t i = 0; i < w->count; i++) {
		int n = snprintf(&buf[off], buf_size - off, "%s%.3f",
				 (i == 0) ? "" : ",", (double)w->samples[i]);
		if (n < 0 || (size_t)(off + n) >= buf_size) {
			return -1;
		}
		off += n;
	}

	int n = snprintf(&buf[off], buf_size - off, "]}");
	if (n < 0 || (size_t)(off + n) >= buf_size) {
		return -1;
	}

	return off + n;
}

int care_event_to_json(const struct care_event *evt, char *buf, size_t buf_size)
{
	int n;

	switch (evt->type) {
	case CARE_EVT_PRESENCE:
		n = snprintf(buf, buf_size,
			     "{\"ts_ms\":%u,\"present\":%s,\"score\":%.2f,"
			     "\"distance_m\":%.2f}",
			     evt->uptime_ms,
			     evt->presence.present ? "true" : "false",
			     (double)evt->presence.score,
			     (double)evt->presence.distance_m);
		break;
	case CARE_EVT_BREATHING:
		n = snprintf(buf, buf_size,
			     "{\"ts_ms\":%u,\"valid\":%s,\"rate_bpm\":%.1f,"
			     "\"confidence\":%.2f}",
			     evt->uptime_ms,
			     evt->breathing.valid ? "true" : "false",
			     (double)evt->breathing.rate_bpm,
			     (double)evt->breathing.confidence);
		break;
	case CARE_EVT_WAVEFORM:
		return waveform_to_json(evt, buf, buf_size);
	case CARE_EVT_FALL:
		n = snprintf(buf, buf_size,
			     "{\"ts_ms\":%u,\"state\":\"%s\",\"confidence\":%.2f,"
			     "\"distance_m\":%.2f}",
			     evt->uptime_ms,
			     fall_state_str(evt->fall.state),
			     (double)evt->fall.confidence,
			     (double)evt->fall.distance_m);
		break;
	default:
		return -1;
	}

	if (n < 0 || (size_t)n >= buf_size) {
		return -1;
	}

	return n;
}
