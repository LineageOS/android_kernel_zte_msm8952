/* Copyright (c) 2008-2016, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/memblock.h>


#define CMDLINE_SDLOG_SIZE          "sdlog.size=0x00000000"
#define CMDLINE_SDLOG_SIZE_PREFIX   "sdlog.size=0x"
#define CMDLINE_SDLOG_ADDR_PREFIX   "sdlog.addr=0x"

#define SDLOG_PARAMETER_LEN					9

static int sdlog_enable;
static unsigned int sdlog_addr;
static int sdlog_size;


static unsigned int sdlog_get_addr_from_command_line(const char *cmd_line)
{
	/*
	* sdlog addr is passed from boot parameter
	* get the addr from command line
	*/
	unsigned long addr = 0;
	char sdlog_addr[SDLOG_PARAMETER_LEN] = {0};

	char *addr_ptr = strnstr(boot_command_line,
			CMDLINE_SDLOG_ADDR_PREFIX,
			strlen(boot_command_line));
	if (!addr_ptr) {
		pr_notice("can not find %s in boot_command_line\n",
			CMDLINE_SDLOG_ADDR_PREFIX);
		return 0;
	}

	strlcpy(sdlog_addr, addr_ptr + strlen(CMDLINE_SDLOG_SIZE_PREFIX),
			sizeof(sdlog_addr));


	if (kstrtoul(sdlog_addr,
			16, &addr)) {
		pr_notice("can not convert %s in boot_command_line\n",
			CMDLINE_SDLOG_ADDR_PREFIX);
		return 0;
	}

	return (unsigned int)addr;
}

static int sdlog_get_size_from_command_line(const char *cmd_line)
{
	/*
	* sdlog size is passed from boot parameter
	* get the size from command line
	*/
	unsigned long size = 0;
	char *size_ptr = NULL;
	char sdlog_size[SDLOG_PARAMETER_LEN] = {0};


	size_ptr = strnstr(boot_command_line, CMDLINE_SDLOG_SIZE_PREFIX,
			strlen(boot_command_line));
	if (!size_ptr) {
		pr_notice("can not find %s in boot_command_line\n",
			CMDLINE_SDLOG_SIZE_PREFIX);
		return 0;
	}

	strlcpy(sdlog_size, size_ptr + strlen(CMDLINE_SDLOG_SIZE_PREFIX),
			sizeof(sdlog_size));

	if (kstrtoul(sdlog_size,
			16, &size)) {
		pr_notice("can not convert %s in boot_command_line\n",
			CMDLINE_SDLOG_SIZE_PREFIX);
		return 0;
	}

	return (int)size;
}


void __init sdlog_memory_reserve(void)
{
	/*
	* sdlog flag is passed from boot parameter
	* set the flag if sdlog is enabled
	*/
	sdlog_size = sdlog_get_size_from_command_line(boot_command_line);
	if (sdlog_size == 0) {
		pr_notice("sdlog disabled, size is 0\n");
		return;
	}

	sdlog_addr = sdlog_get_addr_from_command_line(boot_command_line);
	if (sdlog_addr == 0) {
		pr_notice("sdlog disabled, addr is 0\n");
		return;
	}

	memblock_reserve(sdlog_addr, sdlog_size);
	pr_notice("sdlog enabled, reserve 0x%16lx - 0x%16lx for sdlog (0x%lx byte)\n",
		(unsigned long)sdlog_addr,
		(unsigned long)(sdlog_addr + sdlog_size),
		(unsigned long)sdlog_size);
	sdlog_enable = 1;
}


int sdlog_memory_reserved(void)
{
	pr_notice(" sdlog_memory_reserved sdlog_enable %d\n", sdlog_enable);
	return sdlog_enable;
}
EXPORT_SYMBOL(sdlog_memory_reserved);

unsigned int sdlog_memory_get_addr(void)
{
	return sdlog_addr;
}
EXPORT_SYMBOL(sdlog_memory_get_addr);


int sdlog_memory_get_size(void)
{
	return sdlog_size;
}
EXPORT_SYMBOL(sdlog_memory_get_size);



