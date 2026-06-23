/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Synthetic sensing backend (Phase 0).
 *
 * Emits a plausible stream of presence/breathing/waveform/fall events so the
 * Wi-Fi -> MQTT -> dashboard pipeline can be developed and tested without the
 * A121 sensor or the Acconeer SDK. The scenario loops: room empty -> resident
 * enters and moves -> rests and breathes -> (occasionally) a fall -> recovery.
 */

#include <math.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/atomic.h>

#include "sensing.h"

LOG_MODULE_REGISTER(sensing_synth, CONFIG_LOG_DEFAULT_LEVEL);

#define SYNTH_STACK_SIZE 2048
#define SYNTH_TICK_MS    500

/* Coarse scripted scenario phases (in ticks of SYNTH_TICK_MS). */
enum phase {
	PH_EMPTY,
	PH_ACTIVE,
	PH_RESTING,
	PH_FALL,
	PH_RECOVER,
};

static sensing_event_cb_t evt_cb;
static atomic_t ack_fall_pending;

static float frand(float lo, float hi)
{
	uint32_t r = sys_rand32_get();

	return lo + (hi - lo) * ((float)r / (float)UINT32_MAX);
}

static void emit(const struct care_event *evt)
{
	if (evt_cb != NULL) {
		evt_cb(evt);
	}
}

static void emit_presence(bool present, float score, float dist)
{
	struct care_event e = {
		.type = CARE_EVT_PRESENCE,
		.uptime_ms = k_uptime_get_32(),
		.presence = { .present = present, .score = score, .distance_m = dist },
	};
	emit(&e);
}

static void emit_breathing(bool valid, float bpm, float conf)
{
	struct care_event e = {
		.type = CARE_EVT_BREATHING,
		.uptime_ms = k_uptime_get_32(),
		.breathing = { .valid = valid, .rate_bpm = bpm, .confidence = conf },
	};
	emit(&e);
}

static void emit_waveform(float bpm, float phase)
{
	struct care_event e = {
		.type = CARE_EVT_WAVEFORM,
		.uptime_ms = k_uptime_get_32(),
		.waveform = { .count = CARE_WAVE_MAX_SAMPLES, .fs_hz = 10 },
	};
	float w = 2.0f * 3.14159265f * (bpm / 60.0f) / (float)e.waveform.fs_hz;

	for (uint8_t i = 0; i < e.waveform.count; i++) {
		e.waveform.samples[i] = sinf(phase + w * i) + frand(-0.05f, 0.05f);
	}
	emit(&e);
}

static void emit_fall(enum care_fall_state state, float conf, float dist)
{
	struct care_event e = {
		.type = CARE_EVT_FALL,
		.uptime_ms = k_uptime_get_32(),
		.fall = { .state = state, .confidence = conf, .distance_m = dist },
	};
	emit(&e);
}

static void synth_thread(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	enum phase ph = PH_EMPTY;
	int ticks_in_phase = 0;
	float wave_phase = 0.0f;
	float bpm = 14.0f;

	LOG_INF("Synthetic sensing backend started");

	while (1) {
		k_msleep(SYNTH_TICK_MS);
		ticks_in_phase++;

		if (atomic_cas(&ack_fall_pending, 1, 0) && ph == PH_FALL) {
			LOG_INF("scenario: fall acknowledged, clearing");
			emit_fall(CARE_FALL_NONE, 0.0f, 0.0f);
			ph = PH_RECOVER;
			ticks_in_phase = 0;
		}

		switch (ph) {
		case PH_EMPTY:
			emit_presence(false, frand(0.0f, 0.4f), 0.0f);
			if (ticks_in_phase > 10) {
				ph = PH_ACTIVE;
				ticks_in_phase = 0;
				LOG_INF("scenario: resident entered");
			}
			break;

		case PH_ACTIVE:
			emit_presence(true, frand(2.5f, 5.0f), frand(1.0f, 3.0f));
			if (ticks_in_phase > 16) {
				ph = PH_RESTING;
				ticks_in_phase = 0;
				bpm = frand(12.0f, 18.0f);
				LOG_INF("scenario: resident resting");
			}
			break;

		case PH_RESTING:
			emit_presence(true, frand(1.0f, 2.0f), frand(0.8f, 1.5f));
			bpm += frand(-0.3f, 0.3f);
			emit_breathing(true, bpm, frand(0.7f, 0.95f));
			if (IS_ENABLED(CONFIG_RADAR_CARE_WAVEFORM_STREAM)) {
				emit_waveform(bpm, wave_phase);
				wave_phase += 1.0f;
			}
			if (ticks_in_phase > 30) {
				/* ~1 in 3 rest periods ends in a (simulated) fall. */
				if ((sys_rand32_get() % 3U) == 0U &&
				    IS_ENABLED(CONFIG_RADAR_CARE_FALL_ENABLE)) {
					ph = PH_FALL;
					LOG_WRN("scenario: FALL");
				} else {
					ph = PH_ACTIVE;
					LOG_INF("scenario: resident active again");
				}
				ticks_in_phase = 0;
			}
			break;

		case PH_FALL:
			if (ticks_in_phase == 1) {
				emit_fall(CARE_FALL_SUSPECTED, frand(0.4f, 0.6f), 0.5f);
			} else if (ticks_in_phase == (CONFIG_RADAR_CARE_FALL_SETTLE_MS /
						      SYNTH_TICK_MS)) {
				emit_fall(CARE_FALL_CONFIRMED, frand(0.7f, 0.9f), 0.4f);
			}
			/* On the floor: present, low, only breathing. */
			emit_presence(true, frand(0.5f, 1.0f), 0.4f);
			emit_breathing(true, frand(18.0f, 26.0f), frand(0.5f, 0.7f));
			if (ticks_in_phase > 40) {
				ph = PH_RECOVER;
				ticks_in_phase = 0;
			}
			break;

		case PH_RECOVER:
			emit_fall(CARE_FALL_NONE, 0.0f, 0.0f);
			emit_presence(true, frand(2.0f, 4.0f), frand(1.0f, 2.0f));
			if (ticks_in_phase > 6) {
				ph = PH_EMPTY;
				ticks_in_phase = 0;
				LOG_INF("scenario: resident recovered / left");
			}
			break;
		}
	}
}

K_THREAD_STACK_DEFINE(synth_stack, SYNTH_STACK_SIZE);
static struct k_thread synth_tcb;

int sensing_start(sensing_event_cb_t cb)
{
	evt_cb = cb;

	k_thread_create(&synth_tcb, synth_stack, SYNTH_STACK_SIZE, synth_thread,
			NULL, NULL, NULL, K_PRIO_PREEMPT(7), 0, K_NO_WAIT);
	k_thread_name_set(&synth_tcb, "synth_sensing");

	return 0;
}

void sensing_ack_fall(void)
{
	atomic_set(&ack_fall_pending, 1);
}
