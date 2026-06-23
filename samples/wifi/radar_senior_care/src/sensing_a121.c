/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Acconeer A121 sensing backend.
 *
 * Uses the Acconeer breathing reference application as the unified radar
 * pipeline. The reference app internally drives the presence detector (one
 * sensor configuration runs at a time), so a single measurement loop yields:
 *
 *   - presence/distance/motion scores every frame   -> CARE_EVT_PRESENCE
 *   - an estimated breathing rate when it converges  -> CARE_EVT_BREATHING
 *
 * On top of the presence result we run a lightweight, custom fall heuristic
 * (impact motion spike -> sustained stillness while still present) and emit
 * CARE_EVT_FALL (suspected/confirmed/none). See DESIGN.md §6.5.
 *
 * The measure/calibrate/recalibrate sequence mirrors the Acconeer
 * use_cases/reference_apps/ref_app_breathing_main.c reference.
 */

#include <math.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>

#include "acc_hal_integration_a121.h"
#include "acc_integration.h"
#include "acc_rss_a121.h"
#include "acc_sensor.h"
#include "ref_app_breathing.h"

#include "sensing.h"

LOG_MODULE_REGISTER(sensing_a121, CONFIG_LOG_DEFAULT_LEVEL);

#define A121_STACK_SIZE   8192
#define SENSOR_ID         1U
#define SENSOR_TIMEOUT_MS 1000U
#define CAL_RETRIES       1U

/* Room/zone coverage (metres). Tune for the mounting (DESIGN.md §4.2/D3).
 * Breathing estimation is most reliable for a near, stationary subject; the
 * wider range still serves presence and fall detection.
 */
#define PRESENCE_RANGE_START_M 0.3f
#define PRESENCE_RANGE_END_M   3.0f

/* Anticipated breathing-rate window (BPM). Widened vs. the SITTING preset to
 * cover both calm rest and post-fall distress for seniors.
 */
#define BREATHING_RATE_MIN_BPM 6U
#define BREATHING_RATE_MAX_BPM 30U

/* --- Fall heuristic tunables (DESIGN.md §6.5) ----------------------------- *
 * Intra-frame presence score measures fast motion. A fall is a brief, large
 * motion spike (the impact) followed by the subject staying present but nearly
 * motionless on the floor for a settle window. A downward step in measured
 * distance is used as a corroborating signal (geometry dependent; tune per
 * mounting).
 */
#define FALL_IMPACT_INTRA    8.0f /* spike that may indicate an impact        */
#define FALL_STILL_INTRA     2.0f /* "lying still" upper bound (fast motion)  */
#define FALL_DISTANCE_STEP_M 0.3f /* corroborating sudden distance change     */
#define FALL_RECOVER_INTRA   4.0f /* motion that counts as "got up / active"  */

static sensing_event_cb_t evt_cb;
static atomic_t ack_fall_pending;

static float clampf(float v, float lo, float hi)
{
	if (v < lo) {
		return lo;
	}
	if (v > hi) {
		return hi;
	}
	return v;
}

static void emit_presence(const acc_detector_presence_result_t *r)
{
	if (evt_cb == NULL) {
		return;
	}

	struct care_event e = {
		.type = CARE_EVT_PRESENCE,
		.uptime_ms = k_uptime_get_32(),
		.presence = {
			.present = r->presence_detected,
			.score = MAX(r->intra_presence_score, r->inter_presence_score),
			.distance_m = r->presence_distance,
		},
	};

	evt_cb(&e);
}

static void emit_breathing(float bpm, float confidence)
{
	if (evt_cb == NULL) {
		return;
	}

	struct care_event e = {
		.type = CARE_EVT_BREATHING,
		.uptime_ms = k_uptime_get_32(),
		.breathing = { .valid = true, .rate_bpm = bpm, .confidence = confidence },
	};

	evt_cb(&e);
}

static void emit_fall(enum care_fall_state state, float confidence, float distance_m)
{
	if (evt_cb == NULL) {
		return;
	}

	struct care_event e = {
		.type = CARE_EVT_FALL,
		.uptime_ms = k_uptime_get_32(),
		.fall = { .state = state, .confidence = confidence, .distance_m = distance_m },
	};

	evt_cb(&e);
}

/* --- Fall detector state machine ----------------------------------------- */
enum fall_phase {
	FALL_PH_NORMAL,    /* monitoring                                        */
	FALL_PH_SUSPECTED, /* impact seen, waiting out the settle window        */
	FALL_PH_CONFIRMED, /* latched until the subject is active again / gone  */
};

struct fall_ctx {
	enum fall_phase phase;
	int64_t suspected_since;
	float impact_distance;
	float prev_distance;
	bool have_prev_distance;
};

static void fall_reset(struct fall_ctx *f)
{
	f->phase = FALL_PH_NORMAL;
	f->have_prev_distance = false;
}

/*
 * Run one step of the fall heuristic against a presence result.
 *
 * Transitions:
 *   NORMAL    -> SUSPECTED : present + large intra spike (impact), optionally
 *                            corroborated by a sudden distance step.
 *   SUSPECTED -> CONFIRMED : still present but nearly motionless for the whole
 *                            settle window (CONFIG_RADAR_CARE_FALL_SETTLE_MS).
 *   SUSPECTED -> NORMAL    : subject moved normally again, or left.
 *   CONFIRMED -> NORMAL    : subject became active again, or left the room.
 */
static void fall_step(struct fall_ctx *f, const acc_detector_presence_result_t *r)
{
	const bool present = r->presence_detected;
	const float intra = r->intra_presence_score;
	const float dist = r->presence_distance;
	const int64_t now = k_uptime_get();
	const int64_t settle_ms = CONFIG_RADAR_CARE_FALL_SETTLE_MS;

	float dist_step = 0.0f;

	if (f->have_prev_distance && present) {
		dist_step = fabsf(dist - f->prev_distance);
	}
	if (present) {
		f->prev_distance = dist;
		f->have_prev_distance = true;
	}

	/* Dashboard acknowledged the alert: drop the latch regardless of phase. */
	if (atomic_cas(&ack_fall_pending, 1, 0) && f->phase != FALL_PH_NORMAL) {
		LOG_INF("Fall acknowledged, clearing latch");
		emit_fall(CARE_FALL_NONE, 0.0f, dist);
		f->phase = FALL_PH_NORMAL;
		return;
	}

	switch (f->phase) {
	case FALL_PH_NORMAL:
		if (present && intra >= FALL_IMPACT_INTRA) {
			float conf = clampf(intra / (2.0f * FALL_IMPACT_INTRA), 0.4f, 0.6f);

			if (dist_step >= FALL_DISTANCE_STEP_M) {
				conf = clampf(conf + 0.1f, 0.4f, 0.6f);
			}
			f->phase = FALL_PH_SUSPECTED;
			f->suspected_since = now;
			f->impact_distance = dist;
			LOG_WRN("Fall suspected (intra=%.1f, d=%.2f m)", (double)intra,
				(double)dist);
			emit_fall(CARE_FALL_SUSPECTED, conf, dist);
		}
		break;

	case FALL_PH_SUSPECTED:
		if (!present) {
			/* Left during the window: not a fall (e.g. walked off). */
			LOG_INF("Fall cleared (subject left)");
			emit_fall(CARE_FALL_NONE, 0.0f, 0.0f);
			f->phase = FALL_PH_NORMAL;
		} else if (intra > FALL_STILL_INTRA) {
			/* Moving again before settling: treat as a normal motion. */
			LOG_INF("Fall cleared (subject active)");
			emit_fall(CARE_FALL_NONE, 0.0f, dist);
			f->phase = FALL_PH_NORMAL;
		} else if ((now - f->suspected_since) >= settle_ms) {
			/* Present + still for the whole window -> confirm. */
			float still_s = (float)(now - f->suspected_since) / 1000.0f;
			float conf = clampf(0.6f + 0.05f * still_s, 0.7f, 0.95f);

			LOG_WRN("Fall CONFIRMED (still %.1f s, d=%.2f m)", (double)still_s,
				(double)dist);
			emit_fall(CARE_FALL_CONFIRMED, conf, dist);
			f->phase = FALL_PH_CONFIRMED;
		}
		break;

	case FALL_PH_CONFIRMED:
		if (!present || intra >= FALL_RECOVER_INTRA) {
			LOG_INF("Fall recovered (%s)", present ? "subject active" : "left");
			emit_fall(CARE_FALL_NONE, 0.0f, dist);
			f->phase = FALL_PH_NORMAL;
		}
		break;
	}
}

/* --- Sensor plumbing (mirrors ref_app_breathing_main.c) ------------------ */
static bool sensor_calibration(acc_sensor_t *sensor, acc_cal_result_t *cal_result,
			       void *buffer, uint32_t buffer_size)
{
	bool status = false;
	bool complete = false;

	for (uint16_t i = 0; !status && (i <= CAL_RETRIES); i++) {
		acc_hal_integration_sensor_disable(SENSOR_ID);
		acc_hal_integration_sensor_enable(SENSOR_ID);

		do {
			status = acc_sensor_calibrate(sensor, &complete, cal_result, buffer,
						      buffer_size);
			if (status && !complete) {
				status = acc_hal_integration_wait_for_sensor_interrupt(
					SENSOR_ID, SENSOR_TIMEOUT_MS);
			}
		} while (status && !complete);
	}

	if (status) {
		acc_hal_integration_sensor_disable(SENSOR_ID);
		acc_hal_integration_sensor_enable(SENSOR_ID);
	} else {
		LOG_ERR("acc_sensor_calibrate failed");
	}

	return status;
}

static bool measure(acc_sensor_t *sensor, void *buffer, uint32_t buffer_size)
{
	if (!acc_sensor_measure(sensor)) {
		LOG_ERR("acc_sensor_measure failed");
		return false;
	}
	if (!acc_hal_integration_wait_for_sensor_interrupt(SENSOR_ID, SENSOR_TIMEOUT_MS)) {
		LOG_ERR("sensor interrupt timeout");
		return false;
	}
	if (!acc_sensor_read(sensor, buffer, buffer_size)) {
		LOG_ERR("acc_sensor_read failed");
		return false;
	}

	return true;
}

static void configure(ref_app_breathing_config_t *config)
{
	acc_detector_presence_config_t *pc = config->presence_config;

	acc_detector_presence_config_sensor_set(pc, SENSOR_ID);
	acc_detector_presence_config_start_set(pc, PRESENCE_RANGE_START_M);
	acc_detector_presence_config_end_set(pc, PRESENCE_RANGE_END_M);
	/* Sensitivity for fast motion; same baseline as the SITTING preset. */
	acc_detector_presence_config_intra_detection_threshold_set(pc, 6.0f);

	config->lowest_breathing_rate = BREATHING_RATE_MIN_BPM;
	config->highest_breathing_rate = BREATHING_RATE_MAX_BPM;
}

static void a121_thread(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	ref_app_breathing_config_t *config = NULL;
	ref_app_breathing_handle_t *handle = NULL;
	acc_sensor_t *sensor = NULL;
	acc_cal_result_t cal_result;
	void *buffer = NULL;
	uint32_t buffer_size = 0;
	struct fall_ctx fall;

	fall_reset(&fall);

	if (!acc_rss_hal_register(acc_hal_rss_integration_get_implementation())) {
		LOG_ERR("acc_rss_hal_register failed");
		return;
	}

	config = ref_app_breathing_config_create();
	if (config == NULL) {
		LOG_ERR("breathing config create failed");
		return;
	}

	configure(config);

	handle = ref_app_breathing_create(config);
	if (handle == NULL || !ref_app_breathing_get_buffer_size(handle, &buffer_size)) {
		LOG_ERR("breathing create/buffer_size failed");
		goto cleanup;
	}

	buffer = acc_integration_mem_alloc(buffer_size);
	if (buffer == NULL) {
		LOG_ERR("buffer alloc (%u) failed", buffer_size);
		goto cleanup;
	}

	acc_hal_integration_sensor_supply_on(SENSOR_ID);
	acc_hal_integration_sensor_enable(SENSOR_ID);

	sensor = acc_sensor_create(SENSOR_ID);
	if (sensor == NULL) {
		LOG_ERR("acc_sensor_create failed");
		goto cleanup;
	}

	if (!sensor_calibration(sensor, &cal_result, buffer, buffer_size) ||
	    !ref_app_breathing_prepare(handle, config, sensor, &cal_result, buffer,
				       buffer_size)) {
		LOG_ERR("calibration/prepare failed");
		goto cleanup;
	}

	LOG_INF("A121 breathing+presence running (%.1f-%.1f m), fall detection %s",
		(double)PRESENCE_RANGE_START_M, (double)PRESENCE_RANGE_END_M,
		IS_ENABLED(CONFIG_RADAR_CARE_FALL_ENABLE) ? "on" : "off");

	while (1) {
		ref_app_breathing_result_t result = {0};

		if (!measure(sensor, buffer, buffer_size) ||
		    !ref_app_breathing_process(handle, buffer, &result)) {
			LOG_ERR("measure/process failed");
			break;
		}

		const acc_detector_presence_result_t *pr = &result.presence_result;

		if (pr->processing_result.calibration_needed) {
			LOG_INF("Recalibration needed");
			if (!sensor_calibration(sensor, &cal_result, buffer, buffer_size) ||
			    !ref_app_breathing_prepare(handle, config, sensor, &cal_result,
						       buffer, buffer_size)) {
				LOG_ERR("recalibration failed");
				break;
			}
			continue;
		}

		emit_presence(pr);

		if (result.result_ready) {
			/* The ref app only reports a rate once it has converged
			 * in the ESTIMATE_BREATHING_RATE state; treat that as a
			 * high-confidence reading.
			 */
			emit_breathing(result.breathing_rate, 0.9f);
		}

		if (IS_ENABLED(CONFIG_RADAR_CARE_FALL_ENABLE)) {
			fall_step(&fall, pr);
		}
	}

cleanup:
	if (sensor != NULL) {
		acc_sensor_destroy(sensor);
	}
	acc_hal_integration_sensor_disable(SENSOR_ID);
	acc_hal_integration_sensor_supply_off(SENSOR_ID);
	if (buffer != NULL) {
		acc_integration_mem_free(buffer);
	}
	if (handle != NULL) {
		ref_app_breathing_destroy(handle);
	}
	if (config != NULL) {
		ref_app_breathing_config_destroy(config);
	}

	LOG_ERR("A121 sensing thread exited");
}

K_THREAD_STACK_DEFINE(a121_stack, A121_STACK_SIZE);
static struct k_thread a121_tcb;

int sensing_start(sensing_event_cb_t cb)
{
	evt_cb = cb;

	k_thread_create(&a121_tcb, a121_stack, A121_STACK_SIZE, a121_thread,
			NULL, NULL, NULL, K_PRIO_PREEMPT(6), 0, K_NO_WAIT);
	k_thread_name_set(&a121_tcb, "a121_sensing");

	return 0;
}

void sensing_ack_fall(void)
{
	atomic_set(&ack_fall_pending, 1);
}
