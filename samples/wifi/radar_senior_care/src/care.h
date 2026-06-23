/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef RADAR_CARE_CARE_H_
#define RADAR_CARE_CARE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Maximum number of breathing-waveform samples carried in one event. */
#define CARE_WAVE_MAX_SAMPLES 16

/** Fall detection state. */
enum care_fall_state {
	CARE_FALL_NONE = 0,
	CARE_FALL_SUSPECTED,
	CARE_FALL_CONFIRMED,
};

/** Type discriminator for a care event produced by the sensing backend. */
enum care_event_type {
	CARE_EVT_PRESENCE = 0,
	CARE_EVT_BREATHING,
	CARE_EVT_WAVEFORM,
	CARE_EVT_FALL,
};

struct care_presence {
	bool present;
	float score;
	float distance_m;
};

struct care_breathing {
	bool valid;
	float rate_bpm;
	float confidence;
};

struct care_waveform {
	uint8_t count;
	uint16_t fs_hz;
	float samples[CARE_WAVE_MAX_SAMPLES];
};

struct care_fall {
	enum care_fall_state state;
	float confidence;
	float distance_m;
};

/** A single event emitted by the sensing backend toward telemetry. */
struct care_event {
	enum care_event_type type;
	uint32_t uptime_ms;
	union {
		struct care_presence presence;
		struct care_breathing breathing;
		struct care_waveform waveform;
		struct care_fall fall;
	};
};

/**
 * @brief Serialize a care event into a JSON payload.
 *
 * @return Number of bytes written (excluding NUL), or negative on error.
 */
int care_event_to_json(const struct care_event *evt, char *buf, size_t buf_size);

#endif /* RADAR_CARE_CARE_H_ */
