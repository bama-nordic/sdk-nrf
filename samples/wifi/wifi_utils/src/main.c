/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @brief File containing RPU utils that can be invoked from shell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>

#include "rpu_hw_if.h"

LOG_MODULE_DECLARE(wifi_nrf, CONFIG_WIFI_LOG_LEVEL);

#define SW_VER "2.0"

static int wifi_on_flag;
static bool hl_flag;
static int selected_blk;

enum {
	SHELL_OK = 0,
	SHELL_FAIL = 1
};

void print_memmap(const struct shell *shell)
{
	shell_print(shell, "                                                   \n");
	shell_print(shell, " ==================================================\n");
	shell_print(shell, "         Sheliak memory map                        \n");
	shell_print(shell, " ==================================================\n");
	for (int i = 0; i < NUM_MEM_BLOCKS; i++) {
		shell_print(shell, " %-14s : 0x%06x - 0x%06x (%05d words)\n",
					blk_name[i],
					rpu_7002_memmap[i][0],
					rpu_7002_memmap[i][1],
					1 + ((rpu_7002_memmap[i][1] - rpu_7002_memmap[i][0]) >> 2)
					);
	}
}

/* Convert to shell return values */
static inline int shell_ret(int ret)
{
	if (ret)
		return SHELL_FAIL;
	else
		return SHELL_OK;
}


static int cmd_write_wrd(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t val;
	uint32_t addr;

	addr = strtoul(argv[1], NULL, 0);
	val = strtoul(argv[2], NULL, 0);

	if (wifi_on_flag == 0) {
		shell_print(shell, "Err!! Please run wifi_on first");
		return -1;
	}

	if (argc != 3) {
		shell_print(shell, "incorrect arguments!!");
		shell_print(shell, "$ wifiutils write_wrd <addr> <value>");
		return -1;
	}
	return shell_ret(rpu_write(addr, &val, 4));
}

static int cmd_write_blk(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t pattern;
	uint32_t addr;
	uint32_t num_words;
	uint32_t offset;
	uint32_t *buff;
	int i;

	addr = strtoul(argv[1], NULL, 0);
	pattern = strtoul(argv[2], NULL, 0);
	offset = strtoul(argv[3], NULL, 0);
	num_words = strtoul(argv[4], NULL, 0);

	if (wifi_on_flag == 0) {
		shell_print(shell, "Err!! Please run wifi_on first");
		return -1;
	}

	if (argc != 5) {
		shell_print(shell, "incorrect arguments!!");
		shell_print(shell, "$ wifiutils write_blk <addr> <start_pattern> <pattern_incr>
				<num_words>");
		return -1;
	}

	if (num_words > 2000) {
		shell_print(shell,
				"Presently supporting block read/write only upto 2000 32-bit words");
		return SHELL_FAIL;
	}

	buff = (uint32_t *)k_malloc(num_words * 4);
	for (i = 0; i < num_words; i++) {
		buff[i] = pattern + i * offset;
	}

	if (!rpu_write(addr, buff, num_words * 4))
		return SHELL_FAIL;

	k_free(buff);

	return SHELL_OK;
}

static int cmd_read_wrd(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t val;
	uint32_t addr;

	addr = strtoul(argv[1], NULL, 0);

	if (wifi_on_flag == 0) {
		shell_print(shell, "Err!! Please run wifi_on first");
		return -1;
	}

	if (argc != 2) {
		shell_print(shell, "incorrect arguments!!");
		shell_print(shell, "$ wifiutils read_wrd <addr>");
		return -1;
	}

	if (rpu_read(addr, &val, 4))
		return SHELL_FAIL;

	shell_print(shell, "0x%08x\n", val);
	return SHELL_OK;
}

static int cmd_read_blk(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t *buff;
	uint32_t addr;
	uint32_t num_words;
	uint32_t rem;
	int i;

	addr = strtoul(argv[1], NULL, 0);
	num_words = strtoul(argv[2], NULL, 0);

	if (wifi_on_flag == 0) {
		shell_print(shell, "Err!! Please run wifi_on first");
		return -1;
	}
	if (argc != 3) {
		shell_print(shell, "incorrect arguments!!");
		shell_print(shell, "$ wifiutils read_blk <addr> <num_words>");
	return -1;
	}

	if (num_words > 2000) {
		shell_print(shell,
				"Presently supporting block read/write only upto 2000 32-bit words");
		return SHELL_FAIL;
	}

	buff = (uint32_t *)k_malloc(num_words * 4);

	if (rpu_read(addr, buff, num_words * 4))
		return SHELL_FAIL;

	for (i = 0; i < num_words; i += 4) {
		rem = num_words - i;
		switch (rem) {
		case 1:
			shell_print(shell, "%08x", buff[i]);
			break;
		case 2:
			shell_print(shell, "%08x %08x", buff[i], buff[i + 1]);
			break;
		case 3:
			shell_print(shell, "%08x %08x %08x", buff[i], buff[i + 1], buff[i + 2]);
			break;
		default:
			shell_print(shell, "%08x %08x %08x %08x", buff[i], buff[i + 1], buff[i + 2],
					buff[i + 3]);
			break;
		}
	}

	k_free(buff);
	return SHELL_OK;
}

static int cmd_memtest(const struct shell *shell, size_t argc, char **argv)
{
	/* $write_blk 0xc0000 0xdeadbeef 16 */
	uint32_t pattern;
	uint32_t addr;
	uint32_t num_words;
	uint32_t offset;
	uint32_t *buff, *rxbuff;
	int i;

	addr = strtoul(argv[1], NULL, 0);
	pattern = strtoul(argv[2], NULL, 0);
	offset = strtoul(argv[3], NULL, 0);
	num_words = strtoul(argv[4], NULL, 0);

	if (wifi_on_flag == 0) {
		shell_print(shell, "Err!! Please run wifi_on first");
		return -1;
	}

	if (argc != 5) {
		shell_print(shell, "incorrect arguments!!");
		shell_print(shell, "$ wifiutils memtest <start_addr> <start_pattern>
				<pattern_incr> <num_words>");
		return -1;
	}

	if (!rpu_validate_addr(addr, num_words*4, &hl_flag))
		return -1;

	buff = (uint32_t *) k_malloc(2000*4);
	rxbuff = (uint32_t *) k_malloc(2000*4);

	int32_t rem_words = num_words;
	uint32_t test_chunk, chunk_no = 0;

	while (rem_words > 0) {
		test_chunk = (rem_words < 2000) ? rem_words : 2000;

		for (i = 0; i < test_chunk; i++) {
			buff[i] = pattern + (i + chunk_no * 2000) * offset;
		}

		addr = addr+chunk_no*2000;

		if (rpu_write(addr, buff, test_chunk * 4) ||
			rpu_read(addr, rxbuff, test_chunk * 4)) {
			goto err;
		}

		if (memcmp(buff, rxbuff, test_chunk * 4) != 0) {
			goto err;
		}
		rem_words -= 2000;
		chunk_no++;
	}
	shell_print(shell, "memtest PASSED");
	k_free(rxbuff);
	k_free(buff);

	return SHELL_OK;
err:
	shell_print(shell, "memtest failed");
	k_free(rxbuff);
	k_free(buff);
	return SHELL_FAIL;
}

static int cmd_sleep_stats(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t addr;
	uint32_t wrd_len;
	uint32_t *buff;

	addr = strtoul(argv[1], NULL, 0);
	wrd_len = strtoul(argv[2], NULL, 0);

	if (wifi_on_flag == 0) {
		shell_print(shell, "Err!! Please run wifi_on first");
		return -1;
	}

	if (argc != 3) {
		shell_print(shell, "incorrect arguments!!");
		shell_print(shell, "$ wifiutils sleep_stats <addr> <num_words>");
		return -1;
	}


	if (!rpu_validate_addr(addr, wrd_len*4, &hl_flag))
		return -1;

	if ((selected_blk == LMAC_ROM) || (selected_blk == UMAC_ROM)) {
		shell_print(shell, "Error... Cannot write to ROM blocks");
		return -1;
	}

	buff = (uint32_t *) k_malloc(wrd_len*4);

	rpu_get_sleep_stats(addr, buff, wrd_len);

	for (int i = 0; i < wrd_len; i++) {
		shell_print(shell, "0x%08x\n", buff[i]);
	}

	k_free(buff);
	return SHELL_OK;
}

static int cmd_gpio_config(const struct shell *shell, size_t argc, char **argv)
{
	return shell_ret(rpu_gpio_config());
}

static int cmd_pwron(const struct shell *shell, size_t argc, char **argv)
{
	return shell_ret(rpu_pwron());
}

static int cmd_qspi_init(const struct shell *shell, size_t argc, char **argv)
{
	return shell_ret(rpu_qspi_init());
}

static int cmd_rpuwake(const struct shell *shell, size_t argc, char **argv)
{
	return shell_ret(rpu_wakeup());
}

static int cmd_wrsr2(const struct shell *shell, size_t argc, char **argv)
{
	return shell_ret(rpu_wrsr2(strtoul(argv[1], NULL, 0) & 0xff));
}

static int cmd_rdsr2(const struct shell *shell, size_t argc, char **argv)
{
	uint8_t val = rpu_rdsr2();

	shell_print(shell, "RDSR2 = 0x%x\n", val);

	return SHELL_OK;
}

static int cmd_rdsr1(const struct shell *shell, size_t argc, char **argv)
{
	uint8_t val = rpu_rdsr1();

	shell_print(shell, "RDSR1 = 0x%x\n", val);

	return SHELL_OK;
}

static int cmd_rpuclks_on(const struct shell *shell, size_t argc, char **argv)
{
	return shell_ret(rpu_clks_on());
}

static int cmd_wifi_on(const struct shell *shell, size_t argc, char **argv)
{
	int ret;

	ret = rpu_disable();

	ret = rpu_enable();

	if (ret) {
		shell_print(shell, "Wi-Fi ON failed...");
		return SHELL_FAIL;
	}

	wifi_on_flag = 1;
	return SHELL_OK;
}

static int cmd_wifi_off(const struct shell *shell, size_t argc, char **argv)
{
	int ret;

	ret = rpu_disable();

	if (ret) {
		shell_print(shell, "Wi-Fi OFF failed...");
		return SHELL_FAIL;
	}

	wifi_on_flag = 0;
	return SHELL_OK;
}

static int cmd_memmap(const struct shell *shell, size_t argc, char **argv)
{
	print_memmap(shell);
	return SHELL_OK;
}

static void cmd_help(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Supported commands....  ");
	shell_print(shell, "=========================  ");
	shell_print(shell, "uart:~$ wifiutils read_wrd    <address> ");
	shell_print(shell, "         ex: $ wifiutils read_wrd 0x0c0000");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils write_wrd   <address> <data>");
	shell_print(shell, "         ex: $ wifiutils write_wrd 0x0c0000 0xabcd1234");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils read_blk    <address> <num_words>");
	shell_print(shell, "         ex: $ wifiutils read_blk 0x0c0000 64");
	shell_print(shell, "         Note - num_words can be a maximum of 2000");
	shell_print(shell, "  ");
	shell_print(
		shell,
		"uart:~$ wifiutils write_blk   <address> <start_pattern> <pattern_increment> <num_words>");
	shell_print(shell, "         ex: $ wifiutils write_blk 0x0c0000 0xaaaa5555 0 64");
	shell_print(
		shell,
		"         This writes pattern 0xaaaa5555 to 64 locations starting from 0x0c0000");
	shell_print(shell, "         ex: $ wifiutils write_blk 0x0c0000 0x0 1 64");
	shell_print(
		shell,
		"         This writes pattern 0x0, 0x1,0x2,0x3....etc to 64 locations starting from
		0x0c0000");
	shell_print(shell, "         Note - num_words can be a maximum of 2000");
	shell_print(shell, "  ");
	shell_print(
		shell,
		"uart:~$ wifiutils memtest   <address> <start_pattern> <pattern_increment> <num_words>");
	shell_print(shell, "         ex: $ wifiutils memtest 0x0c0000 0xaaaa5555 0 64");
	shell_print(
		shell,
		"         This writes pattern 0xaaaa5555 to 64 locations starting from 0x0c0000, ");
	shell_print(shell, "         reads them back and validates them");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils wifi_on  ");
#if CONFIG_NRF700X_ON_QSPI
	shell_print(shell, "         - Configures all gpio pins ");
	shell_print(
		shell,
		"         - Writes 1 to BUCKEN, waits for 2ms and then writes 1 to IOVDD Control");
	shell_print(shell, "         - Initializes qspi interface and wakes up RPU");
	shell_print(shell, "         - Enables all gated RPU clocks");
#else
	shell_print(shell, "         - Configures all gpio pins ");
	shell_print(
		shell,
		"         - Writes 1 to BUCKEN, waits for 2ms and then writes 1 to IOVDD Control");
	shell_print(shell, "         - Initializes qspi interface and wakes up RPU");
	shell_print(shell, "         - Enables all gated RPU clocks");
#endif
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils wifi_off ");
#if CONFIG_NRF700X_ON_QSPI
	shell_print(
		shell,
		"         This writes 0 to IOVDD Control and then writes 0 to BUCKEN Control");
#else
	shell_print(
		shell,
		"         This writes 0 to IOVDD Control and then writes 0 to BUCKEN Control");
#endif
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils sleep_stats ");
	shell_print(shell,
		"         This continuously does the RPU sleep/wake cycle and displays stats ");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils gpio_config ");
#if CONFIG_NRF700X_ON_QSPI
	shell_print(
		shell,
		"         Configures BUCKEN as o/p, IOVDD control as output and HOST_IRQ as input");
	shell_print(shell, "         and interruptible with a ISR hooked to it");
#else
	shell_print(
		shell,
		"         Configures BUCKEN as o/p, IOVDD control as output and HOST_IRQ as input");
	shell_print(shell, "         and interruptible with a ISR hooked to it");
#endif
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils qspi_init ");
	shell_print(shell, "         Initializes QSPI driver functions ");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils pwron ");
	shell_print(shell, "         Sets BUCKEN=1, delay, IOVDD cntrl=1 ");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils rpuwake ");
	shell_print(shell, "         Wakeup RPU: Write 0x1 to WRSR2 register");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils rpuclks_on ");
	shell_print(
		shell,
		"         Enables all gated RPU clocks. Only SysBUS and PKTRAM will work w/o this
		setting enabled");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils wrsr2 <val> ");
	shell_print(shell, "         writes <val> (0/1) to WRSR2 reg - takes LSByte of <val>");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils rdsr1 ");
	shell_print(shell, "         Reads RDSR1 Register");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils rdsr2 ");
	shell_print(shell, "         Reads RDSR2 Register");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils trgirq ");
	shell_print(shell, "         Generates IRQ interrupt to host");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils clrirq ");
	shell_print(shell, "         Clears host IRQ generated interrupt");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils xtal_clkout ");
	shell_print(shell, "         Loops XTAL clock out for calibration reference");
	shell_print(shell, "  ");
	shell_print(shell,
		"uart:~$ wifiutils config  <qspi/spi Freq> <mem_block_num> <read_latency>");
	shell_print(shell, "         QSPI/SPI clock freq in MHz : 4/8/16 etc");
	shell_print(shell, "         block num as per memmap (starting from 0) : 0-10");
	shell_print(shell, "         QSPI/SPIM read latency for the selected block : 0-255");
	shell_print(
		shell,
		"         NOTE: need to do a wifi_off and wifi_on for these changes to take effect");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils ver ");
	shell_print(shell, "         Display SW version and other details of the hex file ");
	shell_print(shell, "  ");
	shell_print(shell, "uart:~$ wifiutils help ");
	shell_print(shell, "         Lists all commands with usage example(s) ");
	shell_print(shell, "  ");
}

static int cmd_ver(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "wifiutils Version: %s", SW_VER);
#if CONFIG_NRF700X_ON_QSPI
	shell_print(shell, "Build for QSPI interface on nRF7002 board");
#else
	shell_print(shell,
			"Build for SPIM interface on nRF7002EK+nRF5340DK connected via arduino header");
#endif
	return SHELL_OK;
}

static int cmd_trgirq(const struct shell *shell, size_t argc, char **argv)
{
	int i;
	static const uint32_t irq_regs[][2] = {
		{0x400, 0x20000},
		{0x494, 0x80000000},
		{0x484, 0x7fff7bee}
	};

	shell_print(shell, "Asserting IRQ to HOST");

	for (i = 0; i < ARRAY_SIZE(irq_regs); i++) {
		if (rpu_write(irq_regs[i][0], (const uint32_t *) irq_regs[i][1], 4)) {
			return SHELL_FAIL;
		}
	}

	return SHELL_OK;
}

static int cmd_clrirq(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "de-asserting IRQ to HOST");

	return shell_ret(rpu_write(0x488, (uint32_t *)0x80000000, 4));
}

static int cmd_xtal_clkout(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t val;

	if (wifi_on_flag == 0) {
		shell_print(shell, "Err!! Please run wifi_on first");
		return -1;
	}

	shell_print(shell, "Looping XTAL clock out for reference");

	val = 0x10;
	rpu_write(0x2DC8, &val, 4);
	shell_print(shell, "1");

	val = 0x8F000045;
	rpu_write(0x080000, &val, 4);
	shell_print(shell, "2");

	val = 0x104D4F00;
	rpu_write(0x080004, &val, 4);
	shell_print(shell, "3");

	val = 0x00FA4000;
	rpu_write(0x080008, &val, 4);
	shell_print(shell, "4");

	val = 0x0;
	rpu_write(0x6024, &val, 4);
	shell_print(shell, "5");

	val = 0x20000000;
	rpu_write(0x6020, &val, 4);
	shell_print(shell, "6");

	return SHELL_OK;
}

/* Creating subcommands (level 1 command) array for command "demo". */
SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_wifiutils,
	SHELL_CMD(write_blk, NULL,
		  "Writes a block of words to Sheliak host memory via QSPI interface",
		  cmd_write_blk),
	SHELL_CMD(read_blk, NULL,
		  "Reads a block of words from Sheliak host memory via QSPI interface",
		  cmd_read_blk),
	SHELL_CMD(write_wrd, NULL, "Writes a word to Sheliak host memory via QSPI interface",
		  cmd_write_wrd),
	SHELL_CMD(read_wrd, NULL, "Reads a word from Sheliak host memory via QSPI interface",
		  cmd_read_wrd),
	SHELL_CMD(wifi_on, NULL, "BUCKEN-IOVDD power ON", cmd_wifi_on),
	SHELL_CMD(wifi_off, NULL, "BUCKEN-IOVDD power OFF", cmd_wifi_off),
	SHELL_CMD(sleep_stats, NULL, "Tests Sleep/Wakeup cycles", cmd_sleep_stats),
	SHELL_CMD(gpio_config, NULL, "Configure all GPIOs", cmd_gpio_config),
	SHELL_CMD(qspi_init, NULL, "Initialize QSPI driver functions", cmd_qspi_init),
	SHELL_CMD(pwron, NULL, "BUCKEN=1, delay, IOVDD=1", cmd_pwron),
	SHELL_CMD(rpuwake, NULL, "Wakeup RPU: Write 0x1 to WRSR2 reg", cmd_rpuwake),
	SHELL_CMD(rpuclks_on, NULL, "Enable all RPU gated clocks", cmd_rpuclks_on),
	SHELL_CMD(wrsr2, NULL, "Write to WRSR2 register", cmd_wrsr2),
	SHELL_CMD(rdsr1, NULL, "Read RDSR1 register", cmd_rdsr1),
	SHELL_CMD(rdsr2, NULL, "Read RDSR2 register", cmd_rdsr2),
	SHELL_CMD(trgirq, NULL, "Generates IRQ interrupt to HOST", cmd_trgirq),
	SHELL_CMD(clrirq, NULL, "Clears generated Host IRQ interrupt", cmd_clrirq),
	SHELL_CMD(xtal_clkout, NULL, "Gives of XTAL Clock as reference", cmd_xtal_clkout),
	SHELL_CMD(memmap, NULL, "Gives the full memory map of the Sheliak chip", cmd_memmap),
	SHELL_CMD(memtest, NULL, "Writes, reads back and validates specified memory on Seliak chip",
		  cmd_memtest),
	SHELL_CMD(ver, NULL, "Display SW version of the hex file", cmd_ver),
	SHELL_CMD(help, NULL, "Help with all supported commmands", cmd_help), SHELL_SUBCMD_SET_END);

/* Creating root (level 0) command "wifiutils" */
SHELL_CMD_REGISTER(wifiutils, &sub_wifiutils, "wifiutils commands", NULL)
