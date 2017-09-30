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

#ifndef SDLOG_MEM_RESERVE_H
#define SDLOG_MEM_RESERVE_H

int sdlog_memory_reserved(void);


void __init sdlog_memory_reserve(void);

unsigned int sdlog_memory_get_addr(void);

int sdlog_memory_get_size(void);


#endif
