#
# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(radar_senior_care)

target_sources(app PRIVATE
  src/main.c
  src/care_json.c
  src/net_mqtt.c
)

# Phase 0 / SDK-absent build: simulated radar data so the Wi-Fi -> MQTT ->
# dashboard pipeline can be exercised without the sensor or the Acconeer SDK.
if(CONFIG_RADAR_CARE_SENSOR_SYNTHETIC)
  target_sources(app PRIVATE src/sensing_synthetic.c)
endif()

# Sensor build: links the proprietary Acconeer A121 RSS libraries and compiles
# the breathing reference app + our Zephyr HAL port. The SDK is an EXTERNAL,
# separately licensed dependency and is NOT committed to this repository.
if(CONFIG_RADAR_CARE_SENSOR_A121)
  # SDK location resolution order:
  #   1. ACCONEER_A121_SDK_DIR environment variable (recommended: propagates to
  #      every sysbuild image automatically), then
  #   2. an explicit -DACCONEER_A121_SDK_DIR=... cache override, then
  #      (for sysbuild use the image-namespaced form noted in the README), then
  #   3. the default ~/cortex_m33_gcc.
  if(DEFINED ENV{ACCONEER_A121_SDK_DIR})
    set(ACCONEER_A121_SDK_DIR "$ENV{ACCONEER_A121_SDK_DIR}"
        CACHE PATH "Path to the Acconeer A121 Cortex-M33 SDK" FORCE)
  else()
    set(ACCONEER_A121_SDK_DIR "$ENV{HOME}/cortex_m33_gcc"
        CACHE PATH "Path to the Acconeer A121 Cortex-M33 SDK")
  endif()

  if(NOT EXISTS "${ACCONEER_A121_SDK_DIR}/rss/lib/libacconeer_a121.a")
    message(FATAL_ERROR
      "Acconeer A121 SDK not found at '${ACCONEER_A121_SDK_DIR}'.\n"
      "Set it with: export ACCONEER_A121_SDK_DIR=/path/to/cortex_m33_gcc")
  endif()

  target_include_directories(app PRIVATE
    ${ACCONEER_A121_SDK_DIR}/rss/include
    ${ACCONEER_A121_SDK_DIR}/integration
    ${ACCONEER_A121_SDK_DIR}/algorithms
    ${ACCONEER_A121_SDK_DIR}/use_cases/reference_apps
  )

  target_sources(app PRIVATE
    src/sensing_a121.c
    src/acconeer_hal/acc_hal_zephyr.c
    src/acconeer_hal/acc_integration_zephyr.c
    src/acconeer_hal/acc_integration_log_zephyr.c
    ${ACCONEER_A121_SDK_DIR}/algorithms/acc_algorithm.c
    ${ACCONEER_A121_SDK_DIR}/use_cases/reference_apps/ref_app_breathing.c
  )

  # Order matters: detectors depend on the core RSS library.
  target_link_libraries(app PRIVATE
    ${ACCONEER_A121_SDK_DIR}/rss/lib/libacc_detector_presence_a121.a
    ${ACCONEER_A121_SDK_DIR}/rss/lib/libacc_detector_distance_a121.a
    ${ACCONEER_A121_SDK_DIR}/rss/lib/libacconeer_a121.a
  )
endif()

include(${ZEPHYR_BASE}/samples/net/common/common.cmake)
