/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Zephyr port of the Acconeer A121 sensor HAL. Mirrors the Acconeer STM32
 * single-sensor reference (integration/acc_hal_integration_stm32cube_xe121_
 * single_sensor.c) onto Zephyr SPI + GPIO for the `a121` devicetree node.
 */

#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "acc_definitions_common.h"
#include "acc_hal_definitions_a121.h"
#include "acc_hal_integration_a121.h"
#include "acc_integration.h"
#include "acc_integration_log.h"

LOG_MODULE_DECLARE(acconeer_rss, CONFIG_LOG_DEFAULT_LEVEL);

#define A121_NODE DT_NODELABEL(a121)

BUILD_ASSERT(DT_NODE_EXISTS(A121_NODE),
	     "Missing devicetree node 'a121'; add it via a board overlay");

#define SENSOR_COUNT          1
#define SPI_MAX_TRANSFER_SIZE 65535U

static const struct spi_dt_spec a121_spi =
	SPI_DT_SPEC_GET(A121_NODE, SPI_WORD_SET(8) | SPI_TRANSFER_MSB | SPI_OP_MODE_MASTER, 0);
static const struct gpio_dt_spec a121_enable = GPIO_DT_SPEC_GET(A121_NODE, enable_gpios);
static const struct gpio_dt_spec a121_irq = GPIO_DT_SPEC_GET(A121_NODE, interrupt_gpios);

static struct gpio_callback irq_cb_data;
static K_SEM_DEFINE(irq_sem, 0, 1);
static bool hal_ready;

static void a121_irq_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(cb);
	ARG_UNUSED(pins);

	k_sem_give(&irq_sem);
}

static int a121_hal_setup(void)
{
	int ret;

	if (!spi_is_ready_dt(&a121_spi)) {
		LOG_ERR("A121 SPI bus not ready");
		return -ENODEV;
	}

	if (!gpio_is_ready_dt(&a121_enable) || !gpio_is_ready_dt(&a121_irq)) {
		LOG_ERR("A121 GPIOs not ready");
		return -ENODEV;
	}

	ret = gpio_pin_configure_dt(&a121_enable, GPIO_OUTPUT_INACTIVE);
	if (ret) {
		return ret;
	}

	ret = gpio_pin_configure_dt(&a121_irq, GPIO_INPUT);
	if (ret) {
		return ret;
	}

	ret = gpio_pin_interrupt_configure_dt(&a121_irq, GPIO_INT_EDGE_TO_ACTIVE);
	if (ret) {
		return ret;
	}

	gpio_init_callback(&irq_cb_data, a121_irq_handler, BIT(a121_irq.pin));
	ret = gpio_add_callback(a121_irq.port, &irq_cb_data);
	if (ret) {
		return ret;
	}

	hal_ready = true;
	return 0;
}

static void a121_transfer(acc_sensor_id_t sensor_id, uint8_t *buffer, size_t buffer_size)
{
	ARG_UNUSED(sensor_id);

	if (!hal_ready && a121_hal_setup() != 0) {
		return;
	}

	/* Full-duplex, in-place (RSS uses the same buffer for TX and RX). */
	const struct spi_buf buf = { .buf = buffer, .len = buffer_size };
	const struct spi_buf_set tx = { .buffers = &buf, .count = 1 };
	const struct spi_buf_set rx = { .buffers = &buf, .count = 1 };

	int ret = spi_transceive_dt(&a121_spi, &tx, &rx);

	if (ret < 0) {
		LOG_ERR("SPI transfer failed: %d", ret);
	}
}

void acc_hal_integration_sensor_supply_on(acc_sensor_id_t sensor_id)
{
	ARG_UNUSED(sensor_id);
	/* No separate supply control on the XE121/A121 EVK wiring. */
}

void acc_hal_integration_sensor_supply_off(acc_sensor_id_t sensor_id)
{
	ARG_UNUSED(sensor_id);
}

void acc_hal_integration_sensor_enable(acc_sensor_id_t sensor_id)
{
	ARG_UNUSED(sensor_id);

	if (!hal_ready && a121_hal_setup() != 0) {
		return;
	}

	/* Clear any pending interrupt before enabling. */
	k_sem_reset(&irq_sem);

	(void)gpio_pin_set_dt(&a121_enable, 1);

	/* Allow the sensor crystal to stabilize. */
	acc_integration_sleep_us(2000);
}

void acc_hal_integration_sensor_disable(acc_sensor_id_t sensor_id)
{
	ARG_UNUSED(sensor_id);

	if (!hal_ready) {
		return;
	}

	(void)gpio_pin_set_dt(&a121_enable, 0);
	acc_integration_sleep_us(2000);
}

bool acc_hal_integration_wait_for_sensor_interrupt(acc_sensor_id_t sensor_id, uint32_t timeout_ms)
{
	ARG_UNUSED(sensor_id);

	if (!hal_ready) {
		return false;
	}

	/* The interrupt line is level-high until serviced; if it is already
	 * asserted there is no edge to wait for.
	 */
	if (gpio_pin_get_dt(&a121_irq) == 1) {
		return true;
	}

	if (k_sem_take(&irq_sem, K_MSEC(timeout_ms)) == 0) {
		return true;
	}

	return gpio_pin_get_dt(&a121_irq) == 1;
}

uint16_t acc_hal_integration_sensor_count(void)
{
	return SENSOR_COUNT;
}

const acc_hal_a121_t *acc_hal_rss_integration_get_implementation(void)
{
	static const acc_hal_a121_t hal = {
		.max_spi_transfer_size = SPI_MAX_TRANSFER_SIZE,
		.mem_alloc = acc_integration_mem_alloc,
		.mem_free = acc_integration_mem_free,
		.transfer = a121_transfer,
		.log = acc_integration_log,
		.optimization.transfer16 = NULL,
	};

	return &hal;
}
