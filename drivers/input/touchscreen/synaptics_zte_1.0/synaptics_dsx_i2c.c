/*
 * Synaptics DSX touchscreen driver
 *
 * Copyright (C) 2012 Synaptics Incorporated
 *
 * Copyright (C) 2012 Alexandra Chin <alexandra.chin@tw.synaptics.com>
 * Copyright (C) 2012 Scott Lin <scott.lin@tw.synaptics.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/gpio.h>
#include <linux/regulator/consumer.h>
#include <linux/input/synaptics_dsx_v1_0.h>
#include "synaptics_dsx_i2c.h"
#include "synaptics_dsx_test_reporting.h"
#include "synaptics_dsx_raw_data.h"

#ifdef KERNEL_ABOVE_2_6_38
#include <linux/input/mt.h>
#endif
#include <linux/proc_fs.h>
#include <linux/fb.h>
#include "../touchscreen_fw.h"
#define DRIVER_NAME "syna-touchscreen"
#define INPUT_PHYS_NAME "syna-touchscreen/input0"

#include <linux/rtc.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>

#define TYPE_B_PROTOCOL

#define NO_0D_WHILE_2D
#define REPORT_2D_W

#define RPT_TYPE (1 << 0)
#define RPT_X_LSB (1 << 1)
#define RPT_X_MSB (1 << 2)
#define RPT_Y_LSB (1 << 3)
#define RPT_Y_MSB (1 << 4)
#define RPT_Z (1 << 5)
#define RPT_WX (1 << 6)
#define RPT_WY (1 << 7)
#define RPT_DEFAULT (RPT_TYPE | RPT_X_LSB | RPT_X_MSB | RPT_Y_LSB | RPT_Y_MSB)

#define EXP_FN_WORK_DELAY_MS 1000 /* ms */
#define POLLING_PERIOD 1 /* ms */
#define SYN_I2C_RETRY_TIMES 10
#define MAX_ABS_MT_TOUCH_MAJOR 15

#define CHECK_STATUS_TIMEOUT_MS 100
#define F01_STD_QUERY_LEN 21
#define F01_BUID_ID_OFFSET 18
#define F11_STD_QUERY_LEN 9
#define F11_STD_CTRL_LEN 10
#define F11_STD_DATA_LEN 12

#define NORMAL_OPERATION (0 << 0)
#define SENSOR_SLEEP (1 << 0)
#define NO_SLEEP_OFF (0 << 2)
#define NO_SLEEP_ON (1 << 2)

#define SENSOR_MAX_X 1000
#define SENSOR_MAX_Y 1000
#define MIN_RX_TO_RX 900
#define MAX_RX_TO_RX 1100
#define RAWDATA_PRINT 0

enum device_status {
	STATUS_NO_ERROR = 0x00,
	STATUS_RESET_OCCURRED = 0x01,
	STATUS_INVALID_CONFIG = 0x02,
	STATUS_DEVICE_FAILURE = 0x03,
	STATUS_CONFIG_CRC_FAILURE = 0x04,
	STATUS_FIRMWARE_CRC_FAILURE = 0x05,
	STATUS_CRC_IN_PROGRESS = 0x06
};
char *syn_fwfile_table[SYN_MOUDLE_NUM_MAX] = {
	SYN_TPK_FW_NAME,
	SYN_TURLY_FW_NAME,
	SYN_SUCCESS_FW_NAME,
	SYN_OFILM_FW_NAME,
	SYN_LEAD_FW_NAME,
	SYN_WINTEK_FW_NAME,
	SYN_LAIBAO_FW_NAME,
	SYN_CMI_FW_NAME,
	SYN_ECW_FW_NAME,
	SYN_GOWORLD_FW_NAME,
	SYN_BAOMING_FW_NAME,
	SYN_EACHOPTO_FW_NAME,
	SYN_MUTTO_FW_NAME,
	SYN_JUNDA_FW_NAME,
	SYN_BOE_FW_NAME,
	SYN_TIANMA_FW_NAME,
	SYN_SAMSUNG_FW_NAME,
	SYN_DIJING_FW_NAME,
	SYN_LCE_FW_NAME
};

static int touch_moudle;
extern bool rawdata_flag;
struct synaptics_rmi4_data *bootloader_rmi4_data;

#define VREG_VDD	"vdd"
#define VREG_VBUS	"vcc_i2c"

struct i2c_client *ts_client;
struct synaptics_rmi4_data *syn_ts;
static struct regulator *vdd, *vbus;
extern struct synaptics_rmi4_f54_handle *f54;
extern unsigned char num_of_rx;
extern unsigned char num_of_tx;
static struct workqueue_struct	*syna_rmi4_resume_wq;
static struct work_struct	syna_rmi4_resume_work;

static int synaptics_rmi4_i2c_read(struct synaptics_rmi4_data *rmi4_data,
		unsigned short addr, unsigned char *data,
		unsigned short length);

static int synaptics_rmi4_i2c_write(struct synaptics_rmi4_data *rmi4_data,
		unsigned short addr, unsigned char *data,
		unsigned short length);

static int synaptics_rmi4_reset_device(struct synaptics_rmi4_data *rmi4_data);

static void synaptics_rmi4_swap_axis(struct synaptics_rmi4_data *rmi4_data);

#ifdef CONFIG_HAS_EARLYSUSPEND
static ssize_t synaptics_rmi4_full_pm_cycle_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_full_pm_cycle_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static void synaptics_rmi4_early_suspend(struct early_suspend *h);

static void synaptics_rmi4_late_resume(struct early_suspend *h);

static int synaptics_rmi4_suspend(struct device *dev);

static int synaptics_rmi4_resume(struct device *dev);

#endif

extern int synaptics_rmi4_raw_data_config(int report_type);

static int fb_notifier_callback(struct notifier_block *self,
				unsigned long event, void *data);

int synaptics_rmi4_suspend_pm(void);

void synaptics_rmi4_resume_pm(struct work_struct *work);

static ssize_t synaptics_rmi4_f01_reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static ssize_t synaptics_rmi4_f01_productinfo_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_f01_buildid_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_f01_flashprog_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_susincharge_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static ssize_t synaptics_rmi4_0dbutton_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_0dbutton_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static ssize_t synaptics_rmi4_flipx_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_flipx_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static ssize_t synaptics_rmi4_flipy_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_flipy_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static ssize_t synaptics_rmi4_swap_axes_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

struct synaptics_rmi4_f01_device_status {
	union {
		struct {
			unsigned char status_code:4;
			unsigned char reserved:2;
			unsigned char flash_prog:1;
			unsigned char unconfigured:1;
		} __packed;
		unsigned char data[1];
	};
};

struct synaptics_rmi4_f1a_query {
	union {
		struct {
			unsigned char max_button_count:3;
			unsigned char reserved:5;
			unsigned char has_general_control:1;
			unsigned char has_interrupt_enable:1;
			unsigned char has_multibutton_select:1;
			unsigned char has_tx_rx_map:1;
			unsigned char has_perbutton_threshold:1;
			unsigned char has_release_threshold:1;
			unsigned char has_strongestbtn_hysteresis:1;
			unsigned char has_filter_strength:1;
		} __packed;
		unsigned char data[2];
	};
};

struct synaptics_rmi4_f1a_control_0 {
	union {
		struct {
			unsigned char multibutton_report:2;
			unsigned char filter_mode:2;
			unsigned char reserved:4;
		} __packed;
		unsigned char data[1];
	};
};

struct synaptics_rmi4_f1a_control_3_4 {
	unsigned char transmitterbutton;
	unsigned char receiverbutton;
};

struct synaptics_rmi4_f1a_control {
	struct synaptics_rmi4_f1a_control_0 general_control;
	unsigned char *button_int_enable;
	unsigned char *multi_button;
	struct synaptics_rmi4_f1a_control_3_4 *electrode_map;
	unsigned char *button_threshold;
	unsigned char button_release_threshold;
	unsigned char strongest_button_hysteresis;
	unsigned char filter_strength;
};

struct synaptics_rmi4_f1a_handle {
	int button_bitmask_size;
	unsigned char button_count;
	unsigned char valid_button_count;
	unsigned char *button_data_buffer;
	unsigned char *button_map;
	struct synaptics_rmi4_f1a_query button_query;
	struct synaptics_rmi4_f1a_control button_control;
};

struct synaptics_rmi4_f54_query {
	union {
		struct {
			/* query 0 */
			unsigned char num_of_rx_electrodes;
			/* query 1 */
			unsigned char num_of_tx_electrodes;
			/* query 2 */
			unsigned char f54_query2_b0__1:2;
			unsigned char has_baseline:1;
			unsigned char has_image8:1;
			unsigned char f54_query2_b4__5:2;
			unsigned char has_image16:1;
			unsigned char f54_query2_b7:1;
			/* queries 3.0 and 3.1 */
			unsigned short clock_rate;
			/* query 4 */
			unsigned char touch_controller_family;
			/* query 5 */
			unsigned char has_pixel_touch_threshold_adjustment:1;
			unsigned char f54_query5_b1__7:7;
			/* query 6 */
			unsigned char has_sensor_assignment:1;
			unsigned char has_interference_metric:1;
			unsigned char has_sense_frequency_control:1;
			unsigned char has_firmware_noise_mitigation:1;
			unsigned char has_ctrl11:1;
			unsigned char has_two_byte_report_rate:1;
			unsigned char has_one_byte_report_rate:1;
			unsigned char has_relaxation_control:1;
		} __packed;
		unsigned char data[8];
	};
};

struct synaptics_rmi4_exp_fn {
	enum exp_fn fn_type;
	bool inserted;
	int (*func_init)(struct synaptics_rmi4_data *rmi4_data);
	void (*func_remove)(struct synaptics_rmi4_data *rmi4_data);
	void (*func_attn)(struct synaptics_rmi4_data *rmi4_data,
			unsigned char intr_mask);
	struct list_head link;
};

static struct device_attribute attrs[] = {
#ifdef CONFIG_HAS_EARLYSUSPEND
	__ATTR(full_pm_cycle, 0660,
			synaptics_rmi4_full_pm_cycle_show,
			synaptics_rmi4_full_pm_cycle_store),
#endif
	__ATTR(reset, 0660,
			synaptics_rmi4_show_error,
			synaptics_rmi4_f01_reset_store),
	__ATTR(productinfo, 0660,
			synaptics_rmi4_f01_productinfo_show,
			synaptics_rmi4_store_error),
	__ATTR(buildid, 0660,
			synaptics_rmi4_f01_buildid_show,
			synaptics_rmi4_store_error),
	__ATTR(flashprog, 0660,
			synaptics_rmi4_f01_flashprog_show,
			synaptics_rmi4_store_error),
	__ATTR(0dbutton, 0660,
			synaptics_rmi4_0dbutton_show,
			synaptics_rmi4_0dbutton_store),
	__ATTR(flipx, 0660,
			synaptics_rmi4_flipx_show,
			synaptics_rmi4_flipx_store),
	__ATTR(flipy, 0660,
			synaptics_rmi4_flipy_show,
			synaptics_rmi4_flipy_store),
	__ATTR(swapaxes, 0660,
			synaptics_rmi4_show_error,
			synaptics_rmi4_swap_axes_store),
	__ATTR(susincharge, 0660,
			synaptics_rmi4_show_error,
			synaptics_rmi4_susincharge_store),
};

struct synaptics_rmi4_exp_fn_data {
	bool initialized;
	bool queue_work;
	struct mutex mutex;
	struct list_head list;
	struct delayed_work work;
	struct workqueue_struct *workqueue;
	struct synaptics_rmi4_data *rmi4_data;
};

static struct synaptics_rmi4_exp_fn_data exp_data;


#ifdef CONFIG_HAS_EARLYSUSPEND
static ssize_t synaptics_rmi4_full_pm_cycle_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			rmi4_data->full_pm_cycle);
}

static ssize_t synaptics_rmi4_full_pm_cycle_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int input;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	retval = kstrtouint(buf, 0, &input);
	if (retval)
		return retval;

	rmi4_data->full_pm_cycle = input > 0 ? 1 : 0;

	return count;
}
#endif

static ssize_t synaptics_rmi4_f01_reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned int reset;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	retval = kstrtouint(buf, 0, &reset);
	if (retval)
		return retval;

	if (reset != 1)
		return -EINVAL;

	retval = synaptics_rmi4_reset_device(rmi4_data);
	if (retval < 0) {
		dev_err(dev,
				"%s: Failed to issue reset command, error = %d\n",
				__func__, retval);
		return retval;
	}

	return count;
}

static ssize_t synaptics_rmi4_f01_productinfo_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "0x%02x 0x%02x\n",
			(rmi4_data->rmi4_mod_info.product_info[0]),
			(rmi4_data->rmi4_mod_info.product_info[1]));
}

static ssize_t synaptics_rmi4_f01_buildid_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned int build_id;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

	build_id = (unsigned int)rmi->build_id[0] +
			(unsigned int)rmi->build_id[1] * 0x100 +
			(unsigned int)rmi->build_id[2] * 0x10000;

	return snprintf(buf, PAGE_SIZE, "%u\n",
			build_id);
}

static ssize_t synaptics_rmi4_f01_flashprog_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int retval;
	struct synaptics_rmi4_f01_device_status device_status;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			rmi4_data->f01_data_base_addr,
			device_status.data,
			sizeof(device_status.data));
	if (retval < 0) {
		dev_err(dev,
				"%s: Failed to read device status, error = %d\n",
				__func__, retval);
		return retval;
	}

	return snprintf(buf, PAGE_SIZE, "%u\n",
			device_status.flash_prog);
}

static ssize_t synaptics_rmi4_0dbutton_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			rmi4_data->button_0d_enabled);
}

static ssize_t synaptics_rmi4_0dbutton_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned int input;
	unsigned char ii;
	unsigned char intr_enable;
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

	retval = kstrtouint(buf, 0, &input);
	if (retval)
		return retval;

	input = input > 0 ? 1 : 0;

	if (rmi4_data->button_0d_enabled == input)
		return count;

	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
			if (fhandler->fn_number == SYNAPTICS_RMI4_F1A) {
				ii = fhandler->intr_reg_num;

				retval = synaptics_rmi4_i2c_read(rmi4_data,
						rmi4_data->f01_ctrl_base_addr +
						1 + ii,
						&intr_enable,
						sizeof(intr_enable));
				if (retval < 0)
					return retval;

				if (input == 1)
					intr_enable |= fhandler->intr_mask;
				else
					intr_enable &= ~fhandler->intr_mask;

				retval = synaptics_rmi4_i2c_write(rmi4_data,
						rmi4_data->f01_ctrl_base_addr +
						1 + ii,
						&intr_enable,
						sizeof(intr_enable));
				if (retval < 0)
					return retval;
			}
		}
	}

	rmi4_data->button_0d_enabled = input;

	return count;
}

static ssize_t synaptics_rmi4_flipx_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			rmi4_data->flip_x);
}

static ssize_t synaptics_rmi4_flipx_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned int input;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	retval = kstrtouint(buf, 0, &input);
	if (retval)
		return retval;

	rmi4_data->flip_x = input > 0 ? 1 : 0;

	return count;
}

static ssize_t synaptics_rmi4_flipy_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			rmi4_data->flip_y);
}

static ssize_t synaptics_rmi4_flipy_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned int input;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	retval = kstrtouint(buf, 0, &input);
	if (retval)
		return retval;

	rmi4_data->flip_y = input > 0 ? 1 : 0;

	return count;
}

static ssize_t synaptics_rmi4_swap_axes_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned int input;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	retval = kstrtouint(buf, 0, &input);
	if (retval)
		return retval;
	if (input != 1)
		return -EINVAL;

	synaptics_rmi4_swap_axis(rmi4_data);

	return count;
}

static ssize_t synaptics_rmi4_susincharge_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	synaptics_rmi4_suspend_pm();
	return count;
}

static void synaptics_rmi4_swap_axis(struct synaptics_rmi4_data *rmi4_data)
{
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_device_info *rmi;
	struct i2c_client *client = rmi4_data->i2c_client;
	struct synaptics_rmi4_fn *sensor_tuning = NULL;

	rmi = &(rmi4_data->rmi4_mod_info);

	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
			pr_info("function number 0x%x\n", fhandler->fn_number);
			if (fhandler->fn_number == SYNAPTICS_RMI4_F55)
				sensor_tuning = fhandler;
			if (sensor_tuning == NULL &&
				fhandler->fn_number == SYNAPTICS_RMI4_F54)
				sensor_tuning = fhandler;
		}
	}

	if (sensor_tuning != NULL) {
		int retval = 0;
		unsigned char val;
		unsigned short swap_ctrl_addr;
		unsigned short offset;

		if (sensor_tuning->fn_number == SYNAPTICS_RMI4_F55)
			swap_ctrl_addr = sensor_tuning->full_addr.ctrl_base + 0;
		else {
			struct synaptics_rmi4_f54_query f54_query;

			retval = synaptics_rmi4_i2c_read(rmi4_data,
				sensor_tuning->full_addr.query_base,
				(unsigned char *)f54_query.data,
				sizeof(f54_query.data));
			if (retval < 0)
				dev_err(&client->dev,
				"%s: Failed to read swap control registers\n",
				__func__);

			/* general ctrl 0 */
			offset = 1;
			/* ctrl 1/4/5/6/8.0/8.1/9*/
			if (f54_query.touch_controller_family == 0x00 ||
				f54_query.touch_controller_family == 0x01)
				offset += 7;
			/* ctrl 2/2.1 */
			offset += 2;
			/* ctrl 3 */
			if (f54_query.has_pixel_touch_threshold_adjustment)
				offset++;
			/* ctrl 7*/
			if (f54_query.touch_controller_family == 0x01)
					offset += 1;
			/* ctrl 10 */
			if (f54_query.has_interference_metric)
				offset++;
			/* ctrl 11/11.0 */
			if (f54_query.has_ctrl11)
				offset += 2;
			/* ctrl 12/13 */
			if (f54_query.has_relaxation_control)
				offset += 2;
			if (!f54_query.has_sensor_assignment)
				dev_err(&client->dev,
				"%s: Sensor assignment properties not exist\n",
				__func__);
			swap_ctrl_addr = sensor_tuning->full_addr.ctrl_base + offset;
		}
		retval = synaptics_rmi4_i2c_read(rmi4_data,
				swap_ctrl_addr,
				(unsigned char *)&val,
				sizeof(val));
		if (retval < 0)
			dev_err(&client->dev,
			"%s: Failed to read swap control registers\n",
			__func__);

		val = (val & 0xFE) | (!val & 0x01);

		dev_info(&client->dev,
			"swap value :0x%x, rmi address 0x%02X\n",
			val, swap_ctrl_addr);

		retval = synaptics_rmi4_i2c_write(rmi4_data,
				swap_ctrl_addr,
				(unsigned char *)&val,
				sizeof(val));
		if (retval < 0)
			dev_err(&client->dev,
			"%s: Failed to write swap control registers\n",
			__func__);
	} else
		dev_err(&client->dev,
			"%s: Firmware not support swap function\n",
			__func__);
}

 /**
 * synaptics_rmi4_set_page()
 *
 * Called by synaptics_rmi4_i2c_read() and synaptics_rmi4_i2c_write().
 *
 * This function writes to the page select register to switch to the
 * assigned page.
 */
static int synaptics_rmi4_set_page(struct synaptics_rmi4_data *rmi4_data,
		unsigned int address)
{
	int retval = 0;
	unsigned char retry;
	unsigned char buf[PAGE_SELECT_LEN];
	unsigned char page;
	struct i2c_client *i2c = rmi4_data->i2c_client;

	page = ((address >> 8) & MASK_8BIT);
	if (page != rmi4_data->current_page) {
		buf[0] = MASK_8BIT;
		buf[1] = page;
		for (retry = 0; retry < SYN_I2C_RETRY_TIMES; retry++) {
			retval = i2c_master_send(i2c, buf, PAGE_SELECT_LEN);
			if (retval != PAGE_SELECT_LEN) {
				dev_err(&i2c->dev,
						"%s: I2C retry %d\n",
						__func__, retry + 1);
				msleep(20);
			} else {
				rmi4_data->current_page = page;
				break;
			}
		}
	} else
		return PAGE_SELECT_LEN;
	return (retval == PAGE_SELECT_LEN) ? retval : -EIO;
}

 /**
 * synaptics_rmi4_i2c_read()
 *
 * Called by various functions in this driver, and also exported to
 * other expansion Function modules such as rmi_dev.
 *
 * This function reads data of an arbitrary length from the sensor,
 * starting from an assigned register address of the sensor, via I2C
 * with a retry mechanism.
 */
static int synaptics_rmi4_i2c_read(struct synaptics_rmi4_data *rmi4_data,
		unsigned short addr, unsigned char *data, unsigned short length)
{
	int retval;
	unsigned char retry;
	unsigned char buf;
	struct i2c_msg msg[] = {
		{
			.addr = rmi4_data->i2c_client->addr,
			.flags = 0,
			.len = 1,
			.buf = &buf,
		},
		{
			.addr = rmi4_data->i2c_client->addr,
			.flags = I2C_M_RD,
			.len = length,
			.buf = data,
		},
	};

	buf = addr & MASK_8BIT;

	mutex_lock(&(rmi4_data->rmi4_io_ctrl_mutex));

	retval = synaptics_rmi4_set_page(rmi4_data, addr);
	if (retval != PAGE_SELECT_LEN)
		goto exit;

	for (retry = 0; retry < SYN_I2C_RETRY_TIMES; retry++) {
		if (i2c_transfer(rmi4_data->i2c_client->adapter, msg, 2) == 2) {
			retval = length;
			break;
		}
		dev_err(&rmi4_data->i2c_client->dev,
				"%s: I2C retry %d\n",
				__func__, retry + 1);
		msleep(20);
	}

	if (retry == SYN_I2C_RETRY_TIMES) {
		dev_err(&rmi4_data->i2c_client->dev,
				"%s: I2C read over retry limit\n",
				__func__);
		retval = -EIO;
	}

exit:
	mutex_unlock(&(rmi4_data->rmi4_io_ctrl_mutex));

	return retval;
}

 /**
 * synaptics_rmi4_i2c_write()
 *
 * Called by various functions in this driver, and also exported to
 * other expansion Function modules such as rmi_dev.
 *
 * This function writes data of an arbitrary length to the sensor,
 * starting from an assigned register address of the sensor, via I2C with
 * a retry mechanism.
 */
static int synaptics_rmi4_i2c_write(struct synaptics_rmi4_data *rmi4_data,
		unsigned short addr, unsigned char *data, unsigned short length)
{
	int retval;
	unsigned char retry;
	unsigned char buf[length + 1];
	struct i2c_msg msg[] = {
		{
			.addr = rmi4_data->i2c_client->addr,
			.flags = 0,
			.len = length + 1,
			.buf = buf,
		}
	};

	mutex_lock(&(rmi4_data->rmi4_io_ctrl_mutex));

	retval = synaptics_rmi4_set_page(rmi4_data, addr);
	if (retval != PAGE_SELECT_LEN)
		goto exit;

	buf[0] = addr & MASK_8BIT;
	memcpy(&buf[1], &data[0], length);

	for (retry = 0; retry < SYN_I2C_RETRY_TIMES; retry++) {
		if (i2c_transfer(rmi4_data->i2c_client->adapter, msg, 1) == 1) {
			retval = length;
			break;
		}
		dev_err(&rmi4_data->i2c_client->dev,
				"%s: I2C retry %d\n",
				__func__, retry + 1);
		msleep(20);
	}

	if (retry == SYN_I2C_RETRY_TIMES) {
		dev_err(&rmi4_data->i2c_client->dev,
				"%s: I2C write over retry limit\n",
				__func__);
		retval = -EIO;
	}

exit:
	mutex_unlock(&(rmi4_data->rmi4_io_ctrl_mutex));

	return retval;
}

 /**
 * synaptics_rmi4_f11_abs_report()
 *
 * Called by synaptics_rmi4_report_touch() when valid Function $11
 * finger data has been detected.
 *
 * This function reads the Function $11 data registers, determines the
 * status of each finger supported by the Function, processes any
 * necessary coordinate manipulation, reports the finger data to
 * the input subsystem, and returns the number of fingers detected.
 */
static struct timespec timespec;
static struct rtc_time time;

#define NR_FINGERS	10
static DECLARE_BITMAP(pre_fingers, NR_FINGERS);
/*static int add_log = 0;*/

static int synaptics_rmi4_f11_abs_report(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler)
{
	int retval;
	unsigned char touch_count = 0; /* number of touch points */
	unsigned char reg_index;
	unsigned char finger;
	unsigned char fingers_supported;
	unsigned char num_of_finger_status_regs;
	unsigned char finger_shift;
	unsigned char finger_status;
	unsigned char data_reg_blk_size;
	unsigned char finger_status_reg[3];
	unsigned char data[F11_STD_DATA_LEN];
	unsigned short data_addr;
	unsigned short data_offset;
	int x;
	int y;
	int wx;
	int wy;
	int z;

	/*
	 * The number of finger status registers is determined by the
	 * maximum number of fingers supported - 2 bits per finger. So
	 * the number of finger status registers to read is:
	 * register_count = ceil(max_num_of_fingers / 4)
	 */
	fingers_supported = fhandler->num_of_data_points;
	num_of_finger_status_regs = (fingers_supported + 3) / 4;
	data_addr = fhandler->full_addr.data_base;
	data_reg_blk_size = fhandler->size_of_data_register_block;

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			data_addr,
			finger_status_reg,
			num_of_finger_status_regs);
	if (retval < 0)
		return 0;

	for (finger = 0; finger < fingers_supported; finger++) {
		reg_index = finger / 4;
		finger_shift = (finger % 4) * 2;
		finger_status = (finger_status_reg[reg_index] >> finger_shift)
				& MASK_2BIT;
		if (finger_status) {
			__set_bit(finger, pre_fingers);
		} else if (test_bit(finger, pre_fingers)) {
			__clear_bit(finger, pre_fingers);
		}
		/*
		 * Each 2-bit finger status field represents the following:
		 * 00 = finger not present
		 * 01 = finger present and data accurate
		 * 10 = finger present but data may be inaccurate
		 * 11 = reserved
		 */
#ifdef TYPE_B_PROTOCOL
		input_mt_slot(rmi4_data->input_dev, finger);
		input_mt_report_slot_state(rmi4_data->input_dev,
				MT_TOOL_FINGER, finger_status != 0);
#endif

		if (finger_status) {
			data_offset = data_addr +
					num_of_finger_status_regs +
					(finger * data_reg_blk_size);
			retval = synaptics_rmi4_i2c_read(rmi4_data,
					data_offset,
					data,
					data_reg_blk_size);
			if (retval < 0)
				return 0;

			x = (data[0] << 4) | (data[2] & MASK_4BIT);
			y = (data[1] << 4) | ((data[2] >> 4) & MASK_4BIT);
			wx = (data[3] & MASK_4BIT);
			wy = (data[3] >> 4) & MASK_4BIT;
			z = data[4];

			if (rmi4_data->flip_x)
				x = rmi4_data->sensor_max_x - x;
			if (rmi4_data->flip_y)
				y = rmi4_data->sensor_max_y - y;

			dev_dbg(&rmi4_data->i2c_client->dev,
					"%s: Finger %d:\n"
					"status = 0x%02x\n"
					"x = %d\n"
					"y = %d\n"
					"wx = %d\n"
					"wy = %d\n",
					__func__, finger,
					finger_status,
					x, y, wx, wy);

			input_report_key(rmi4_data->input_dev,
					BTN_TOUCH, 1);
			input_report_key(rmi4_data->input_dev,
					BTN_TOOL_FINGER, 1);
			input_report_abs(rmi4_data->input_dev,
					ABS_MT_POSITION_X, x);
			input_report_abs(rmi4_data->input_dev,
					ABS_MT_POSITION_Y, y);
			input_report_abs(rmi4_data->input_dev,
					ABS_MT_PRESSURE, z);

#ifdef REPORT_2D_W
			input_report_abs(rmi4_data->input_dev,
					ABS_MT_TOUCH_MAJOR, max(wx, wy));
			input_report_abs(rmi4_data->input_dev,
					ABS_MT_TOUCH_MINOR, min(wx, wy));
#endif
#ifndef TYPE_B_PROTOCOL
			input_mt_sync(rmi4_data->input_dev);
#endif
			touch_count++;
		}
	}
#ifndef TYPE_B_PROTOCOL
	if (!touch_count)
		input_mt_sync(rmi4_data->input_dev);
#else
	/* sync after groups of events */
	#ifdef KERNEL_ABOVE_3_7
	input_mt_sync_frame(rmi4_data->input_dev);
	#endif
#endif

	input_sync(rmi4_data->input_dev);

	return touch_count;
}

static void synaptics_rmi4_f1a_report(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler)
{
	int retval;
	int x = 0, y = 0;
	unsigned char button;
	unsigned char index;
	unsigned char shift;
	unsigned char status;
	unsigned char *data;
	unsigned short data_addr = fhandler->full_addr.data_base;
	struct synaptics_rmi4_f1a_handle *f1a = fhandler->data;
	static unsigned char do_once = 1;
	static bool current_status[MAX_NUMBER_OF_BUTTONS];
#ifdef NO_0D_WHILE_2D
	static bool before_2d_status[MAX_NUMBER_OF_BUTTONS];
	static bool while_2d_status[MAX_NUMBER_OF_BUTTONS];
#endif

	if (do_once) {
		memset(current_status, 0, sizeof(current_status));
#ifdef NO_0D_WHILE_2D
		memset(before_2d_status, 0, sizeof(before_2d_status));
		memset(while_2d_status, 0, sizeof(while_2d_status));
#endif
		do_once = 0;
	}

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			data_addr,
			f1a->button_data_buffer,
			f1a->button_bitmask_size);
	if (retval < 0) {
		dev_err(&rmi4_data->i2c_client->dev,
				"%s: Failed to read button data registers\n",
				__func__);
		return;
	}

	data = f1a->button_data_buffer;

	for (button = 0; button < f1a->valid_button_count; button++) {
		index = button / 8;
		shift = button % 8;
		status = ((data[index] >> shift) & MASK_1BIT);

		if (current_status[button] == status)
			continue;
		else
			current_status[button] = status;

		pr_info("%s: Button %d (code %d) ->%d\n",
				__func__, button,
				f1a->button_map[button],
				status);
		switch (button) {
		case 0:
			x = syn_ts->sensor_max_x * 50 / 320;
			break;
		case 1:
			x = syn_ts->sensor_max_x * 160 / 320;
			break;
		case 2:
			x = syn_ts->sensor_max_x * 270 / 320;
			break;
		default:
			break;
		}
		y = syn_ts->sensor_max_y * 520 / 480;

#ifdef TYPE_B_PROTOCOL
		input_mt_slot(rmi4_data->input_dev, 0);
		input_mt_report_slot_state(rmi4_data->input_dev,
				MT_TOOL_FINGER, status != 0);
#endif
#ifdef NO_0D_WHILE_2D
		if (rmi4_data->fingers_on_2d == false) {
			if (status == 1) {
				before_2d_status[button] = 1;
			} else {
				if (while_2d_status[button] == 1) {
					while_2d_status[button] = 0;
					continue;
				} else {
					before_2d_status[button] = 0;
				}
			}

			if (status != 0) {
				input_report_key(rmi4_data->input_dev,
					BTN_TOUCH, 1);
				input_report_key(rmi4_data->input_dev,
					BTN_TOOL_FINGER, 1);
				input_report_abs(rmi4_data->input_dev,
					ABS_MT_POSITION_X, x);
				input_report_abs(rmi4_data->input_dev,
					ABS_MT_POSITION_Y, y);
				input_report_abs(rmi4_data->input_dev,
					ABS_MT_PRESSURE, status);
			}
		} else {
			if (before_2d_status[button] == 1) {
				before_2d_status[button] = 0;
				if (status != 0)	{
					input_report_key(rmi4_data->input_dev,
						BTN_TOUCH, 1);
					input_report_key(rmi4_data->input_dev,
						BTN_TOOL_FINGER, 1);
					input_report_abs(rmi4_data->input_dev,
						ABS_MT_POSITION_X, x);
					input_report_abs(rmi4_data->input_dev,
						ABS_MT_POSITION_Y, y);
					input_report_abs(rmi4_data->input_dev,
						ABS_MT_PRESSURE, status);
				}
			} else {
				if (status == 1)
					while_2d_status[button] = 1;
				else
					while_2d_status[button] = 0;
			}
		}
#else
		if (status != 0) {
			input_report_key(rmi4_data->input_dev,
				BTN_TOUCH, 1);
			input_report_key(rmi4_data->input_dev,
				BTN_TOOL_FINGER, 1);
			input_report_abs(rmi4_data->input_dev,
				ABS_MT_POSITION_X, x);
			input_report_abs(rmi4_data->input_dev,
				ABS_MT_POSITION_Y, y);
			input_report_abs(rmi4_data->input_dev,
				ABS_MT_PRESSURE, status);
		}
#endif
	}

	input_sync(rmi4_data->input_dev);
}

 /**
 * synaptics_rmi4_report_touch()
 *
 * Called by synaptics_rmi4_sensor_report().
 *
 * This function calls the appropriate finger data reporting function
 * based on the function handler it receives and returns the number of
 * fingers detected.
 */
static void synaptics_rmi4_report_touch(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler,
		unsigned char *touch_count)
{
	unsigned char touch_count_2d;

	dev_dbg(&rmi4_data->i2c_client->dev,
			"%s: Function %02x reporting\n",
			__func__, fhandler->fn_number);

	switch (fhandler->fn_number) {
	case SYNAPTICS_RMI4_F11:
		touch_count_2d = synaptics_rmi4_f11_abs_report(rmi4_data,
				fhandler);

		*touch_count += touch_count_2d;

		if (touch_count_2d)
			rmi4_data->fingers_on_2d = true;
		else
			rmi4_data->fingers_on_2d = false;
		break;

	case SYNAPTICS_RMI4_F1A:
		synaptics_rmi4_f1a_report(rmi4_data, fhandler);
		break;

	default:
		break;
	}
}

 /**
 * synaptics_rmi4_sensor_report()
 *
 * Called by synaptics_rmi4_irq().
 *
 * This function determines the interrupt source(s) from the sensor
 * and calls synaptics_rmi4_report_touch() with the appropriate
 * function handler for each function with valid data inputs.
 */
static int synaptics_rmi4_sensor_report(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned char touch_count = 0;
	unsigned char intr[MAX_INTR_REGISTERS];
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_exp_fn *exp_fhandler;
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

	/*
	 * Get interrupt status information from F01 Data1 register to
	 * determine the source(s) that are flagging the interrupt.
	 */
	retval = synaptics_rmi4_i2c_read(rmi4_data,
			rmi4_data->f01_data_base_addr + 1,
			intr,
			rmi4_data->num_of_intr_regs);
	if (retval < 0)
		return retval;

	/*
	 * Traverse the function handler list and service the source(s)
	 * of the interrupt accordingly.
	 */
	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
			if (fhandler->num_of_data_sources) {
				if (fhandler->intr_mask &
						intr[fhandler->intr_reg_num]) {
					synaptics_rmi4_report_touch(rmi4_data,
							fhandler, &touch_count);
				}
			}
		}
	}

	mutex_lock(&exp_data.mutex);
	if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link) {
			if (exp_fhandler->inserted &&
					(exp_fhandler->func_attn != NULL))
				exp_fhandler->func_attn(rmi4_data, intr[0]);
		}
	}
	mutex_unlock(&exp_data.mutex);

	return touch_count;
}

static void synaptics_work_func(struct work_struct *work)
{
	 struct synaptics_rmi4_data *ts = container_of(work, struct synaptics_rmi4_data, work);

	 synaptics_rmi4_sensor_report(ts);
	 enable_irq(ts->irq);

	 return;

}
static struct workqueue_struct *synaptics_wq;

 /**
 * synaptics_rmi4_irq()
 *
 * Called by the kernel when an interrupt occurs (when the sensor
 * asserts the attention irq).
 *
 * This function is the ISR thread and handles the acquisition
 * and the reporting of finger data when the presence of fingers
 * is detected.
 */
static irqreturn_t synaptics_rmi4_irq(int irq, void *data)
{
	struct synaptics_rmi4_data *rmi4_data = data;

	disable_irq_nosync(irq);
	queue_work(synaptics_wq, &rmi4_data->work);

	return IRQ_HANDLED;
}

 /**
 * synaptics_rmi4_irq_enable()
 *
 * Called by synaptics_rmi4_irq_acquire() and power management
 * functions in this driver
 *
 * This function handles the enabling and disabling of the attention
 * irq including the setting up of the ISR thread.
 */
static int synaptics_rmi4_irq_enable(struct synaptics_rmi4_data *rmi4_data,
	bool enable)
{
	int retval = 0;
	unsigned char intr_status;

	if (enable) {
		/* Clear interrupts first */
		retval = synaptics_rmi4_i2c_read(rmi4_data,
				rmi4_data->f01_data_base_addr + 1,
				&intr_status,
				rmi4_data->num_of_intr_regs);
		if (retval < 0)
			return retval;

		enable_irq(rmi4_data->irq);
	} else
		disable_irq(rmi4_data->irq);

	return retval;
}

 /**
 * synaptics_rmi4_irq_acquire()
 *
 * Called by synaptics_rmi4_probe()  in this driver and also exported
 * to other expansion Function modules such as rmi_dev.
 *
 * This function handles the enabling and disabling of the attention
 * irq including the setting up of the ISR thread.
 */
static int synaptics_rmi4_irq_acquire(struct synaptics_rmi4_data *rmi4_data,
		bool enable)
{
	int retval = 0;
	const struct synaptics_dsx_platform_data *pdata = rmi4_data->board;
		unsigned char intr_status;

	if (enable) {
		/* Clear interrupts first */
		retval = synaptics_rmi4_i2c_read(rmi4_data,
				rmi4_data->f01_data_base_addr + 1,
				&intr_status,
				rmi4_data->num_of_intr_regs);
		if (retval < 0) {
			pr_info("synaptics_rmi4_i2c_read fail addr:0x%x, length:%d",
				rmi4_data->f01_data_base_addr + 1, rmi4_data->num_of_intr_regs);
			return retval;
		}
		retval = request_irq(rmi4_data->irq,
			synaptics_rmi4_irq, pdata->irq_flags,
			DRIVER_NAME, rmi4_data);
		if (retval < 0) {
			dev_err(&rmi4_data->i2c_client->dev,
			"%s: Failed to request_threaded_irq\n",
			__func__);
			return retval;
		}
	} else
		free_irq(rmi4_data->irq, rmi4_data);
	return retval;
}

 /**
 * synaptics_rmi4_f11_init()
 *
 * Called by synaptics_rmi4_query_device().
 *
 * This function parses information from the Function 11 registers
 * and determines the number of fingers supported, x and y data ranges,
 * offset to the associated interrupt status register, interrupt bit
 * mask, and gathers finger data acquisition capabilities from the query
 * registers.
 */
static int synaptics_rmi4_f11_init(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler,
		struct synaptics_rmi4_fn_desc *fd,
		unsigned int intr_count)
{
	int retval;
	unsigned char ii;
	unsigned char intr_offset;
	unsigned char abs_data_size;
	unsigned char abs_data_blk_size;
	unsigned char query[F11_STD_QUERY_LEN];
	unsigned char control[F11_STD_CTRL_LEN];

	fhandler->fn_number = fd->fn_number;
	fhandler->num_of_data_sources = fd->intr_src_count;

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			fhandler->full_addr.query_base,
			query,
			sizeof(query));
	if (retval < 0)
		return retval;

	/* Maximum number of fingers supported */
	if ((query[1] & MASK_3BIT) <= 4)
		fhandler->num_of_data_points = (query[1] & MASK_3BIT) + 1;
	else if ((query[1] & MASK_3BIT) == 5)
		fhandler->num_of_data_points = 10;

	rmi4_data->num_of_fingers = fhandler->num_of_data_points;

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			fhandler->full_addr.ctrl_base,
			control,
			sizeof(control));
	if (retval < 0)
		return retval;

	/* Maximum x and y */
	rmi4_data->sensor_max_x = ((control[6] & MASK_8BIT) << 0) |
			((control[7] & MASK_4BIT) << 8);
	rmi4_data->sensor_max_y = ((control[8] & MASK_8BIT) << 0) |
			((control[9] & MASK_4BIT) << 8);
	pr_info("%s: Function %02x max x = %d max y = %d\n",
			__func__, fhandler->fn_number,
			rmi4_data->sensor_max_x,
			rmi4_data->sensor_max_y);

	fhandler->intr_reg_num = (intr_count + 7) / 8;
	if (fhandler->intr_reg_num != 0)
		fhandler->intr_reg_num -= 1;

	/* Set an enable bit for each data source */
	intr_offset = intr_count % 8;
	fhandler->intr_mask = 0;
	for (ii = intr_offset;
			ii < ((fd->intr_src_count & MASK_3BIT) +
			intr_offset);
			ii++)
		fhandler->intr_mask |= 1 << ii;

	abs_data_size = query[5] & MASK_2BIT;
	abs_data_blk_size = 3 + (2 * (abs_data_size == 0 ? 1 : 0));
	fhandler->size_of_data_register_block = abs_data_blk_size;

	return retval;
}

static int synaptics_rmi4_f1a_alloc_mem(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler)
{
	int retval;
	struct synaptics_rmi4_f1a_handle *f1a;

	f1a = kzalloc(sizeof(*f1a), GFP_KERNEL);
	if (!f1a)
		return -ENOMEM;

	fhandler->data = (void *)f1a;

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			fhandler->full_addr.query_base,
			f1a->button_query.data,
			sizeof(f1a->button_query.data));
	if (retval < 0) {
		dev_err(&rmi4_data->i2c_client->dev,
				"%s: Failed to read query registers\n",
				__func__);
		return retval;
	}

	f1a->button_count = f1a->button_query.max_button_count + 1;
	f1a->button_bitmask_size = (f1a->button_count + 7) / 8;

	f1a->button_data_buffer = kcalloc(f1a->button_bitmask_size,
			sizeof(*(f1a->button_data_buffer)), GFP_KERNEL);
	if (!f1a->button_data_buffer)
		return -ENOMEM;

	f1a->button_map = kcalloc(f1a->button_count,
			sizeof(*(f1a->button_map)), GFP_KERNEL);
	if (!f1a->button_map)
		return -ENOMEM;

	return 0;
}

static int synaptics_rmi4_cap_button_map(
				struct synaptics_rmi4_data *rmi4_data,
				struct synaptics_rmi4_fn *fhandler)
{
	unsigned char ii;
	struct synaptics_rmi4_f1a_handle *f1a = fhandler->data;
	const struct synaptics_dsx_platform_data *pdata = rmi4_data->board;

	if (!pdata->cap_button_map)
		return -ENODEV;
	else if (!pdata->cap_button_map->map)
		return -ENODEV;

	if (pdata->cap_button_map->nbuttons !=
		f1a->button_count) {
		f1a->valid_button_count = min(f1a->button_count,
			pdata->cap_button_map->nbuttons);
	} else {
		f1a->valid_button_count = f1a->button_count;
	}

	for (ii = 0; ii < f1a->valid_button_count; ii++)
		f1a->button_map[ii] =
				pdata->cap_button_map->map[ii];

	return 0;
}

static void synaptics_rmi4_f1a_kfree(struct synaptics_rmi4_fn *fhandler)
{
	struct synaptics_rmi4_f1a_handle *f1a = fhandler->data;

	if (f1a) {
		kfree(f1a->button_data_buffer);
		kfree(f1a->button_map);
		kfree(f1a);
		fhandler->data = NULL;
	}
}

static int synaptics_rmi4_f1a_init(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler,
		struct synaptics_rmi4_fn_desc *fd,
		unsigned int intr_count)
{
	int retval;
	unsigned char ii;
	unsigned short intr_offset;

	fhandler->fn_number = fd->fn_number;
	fhandler->num_of_data_sources = fd->intr_src_count;

	fhandler->intr_reg_num = (intr_count + 7) / 8;
	if (fhandler->intr_reg_num != 0)
		fhandler->intr_reg_num -= 1;

	/* Set an enable bit for each data source */
	intr_offset = intr_count % 8;
	fhandler->intr_mask = 0;
	for (ii = intr_offset;
			ii < ((fd->intr_src_count & MASK_3BIT) +
			intr_offset);
			ii++)
		fhandler->intr_mask |= 1 << ii;

	retval = synaptics_rmi4_f1a_alloc_mem(rmi4_data, fhandler);
	if (retval < 0)
		goto error_exit;

	retval = synaptics_rmi4_cap_button_map(rmi4_data, fhandler);
	if (retval < 0)
		goto error_exit;

	rmi4_data->button_0d_enabled = 1;

	return 0;

error_exit:
	synaptics_rmi4_f1a_kfree(fhandler);

	return retval;
}

static int synaptics_rmi4_alloc_fh(struct synaptics_rmi4_fn **fhandler,
		struct synaptics_rmi4_fn_desc *rmi_fd, int page_number)
{
	*fhandler = kzalloc(sizeof(**fhandler), GFP_KERNEL);
	if (!(*fhandler))
		return -ENOMEM;

	(*fhandler)->full_addr.data_base =
			(rmi_fd->data_base_addr |
			(page_number << 8));
	(*fhandler)->full_addr.ctrl_base =
			(rmi_fd->ctrl_base_addr |
			(page_number << 8));
	(*fhandler)->full_addr.cmd_base =
			(rmi_fd->cmd_base_addr |
			(page_number << 8));
	(*fhandler)->full_addr.query_base =
			(rmi_fd->query_base_addr |
			(page_number << 8));
	(*fhandler)->fn_number = rmi_fd->fn_number;

	return 0;
}


 /**
 * synaptics_rmi4_query_device_info()
 *
 * Called by synaptics_rmi4_query_device().
 *
 */
static int synaptics_rmi4_query_device_info(
					struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned char f01_query[F01_STD_QUERY_LEN];
	struct synaptics_rmi4_device_info *rmi = &(rmi4_data->rmi4_mod_info);

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			rmi4_data->f01_query_base_addr,
			f01_query,
			sizeof(f01_query));
	if (retval < 0)
		return retval;

	/* RMI Version 4.0 currently supported */
	rmi->version_major = 4;
	rmi->version_minor = 0;

	rmi->manufacturer_id = f01_query[0];
	rmi->product_props = f01_query[1];
	rmi->product_info[0] = f01_query[2] & MASK_7BIT;
	rmi->product_info[1] = f01_query[3] & MASK_7BIT;
	rmi->date_code[0] = f01_query[4] & MASK_5BIT;
	rmi->date_code[1] = f01_query[5] & MASK_4BIT;
	rmi->date_code[2] = f01_query[6] & MASK_5BIT;
	rmi->tester_id = ((f01_query[7] & MASK_7BIT) << 8) |
			(f01_query[8] & MASK_7BIT);
	rmi->serial_number = ((f01_query[9] & MASK_7BIT) << 8) |
			(f01_query[10] & MASK_7BIT);
	memcpy(rmi->product_id_string, &f01_query[11], 10);

	if (rmi->manufacturer_id != 1) {
		dev_err(&rmi4_data->i2c_client->dev,
				"%s: Non-Synaptics device found, manufacturer ID = %d\n",
				__func__, rmi->manufacturer_id);
	}

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			rmi4_data->f01_query_base_addr + F01_BUID_ID_OFFSET,
			rmi->build_id,
			sizeof(rmi->build_id));
	if (retval < 0) {
		dev_err(&rmi4_data->i2c_client->dev,
				"%s: Failed to read firmware build id (code %d)\n",
				__func__, retval);
		return retval;
	}
	return 0;
}

 /**
 * synaptics_rmi4_crc_in_progress()
 *
 * Check if crc in progress ever occurred
 *
 */
static bool synaptics_rmi4_crc_in_progress(struct synaptics_rmi4_data *rmi4_data,
			struct synaptics_rmi4_f01_device_status *status)
{
	int retval;
	int times = 0;
	bool rescan = false;

	while (1) {
		retval = synaptics_rmi4_i2c_read(rmi4_data,
				rmi4_data->f01_data_base_addr,
				status->data,
				sizeof(status->data));
		if (retval < 0) {
			dev_err(&rmi4_data->i2c_client->dev,
				"%s: read status register failed\n",
				__func__);
			return false;
		}
		if (status->status_code ==
			STATUS_CRC_IN_PROGRESS) {
			dev_info(&rmi4_data->i2c_client->dev,
				"%s: CRC is in progress...\n",
				__func__);
			rescan = true;
			msleep(20);
		} else {
			break;
		}
		if (times++ > 500)
			return false;
	}
	return rescan;
}

 /**
 * synaptics_rmi4_query_device()
 *
 * Called by synaptics_rmi4_probe().
 *
 * This function scans the page description table, records the offsets
 * to the register types of Function $01, sets up the function handlers
 * for Function $11 and Function $12, determines the number of interrupt
 * sources from the sensor, adds valid Functions with data inputs to the
 * Function linked list, parses information from the query registers of
 * Function $01, and enables the interrupt sources from the valid Functions
 * with data inputs.
 */
static int synaptics_rmi4_query_device(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned char ii;
	unsigned char page_number;
	unsigned char intr_count;
	unsigned char data_sources;
	unsigned short pdt_entry_addr;
	unsigned short intr_addr;
	struct synaptics_rmi4_f01_device_status status;
	struct synaptics_rmi4_fn_desc rmi_fd;
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

rescan:
	INIT_LIST_HEAD(&rmi->support_fn_list);
	intr_count = 0;
	data_sources = 0;


	/* Scan the page description tables of the pages to service */
	for (page_number = 0; page_number < PAGES_TO_SERVICE; page_number++) {
		for (pdt_entry_addr = PDT_START; pdt_entry_addr > PDT_END;
				pdt_entry_addr -= PDT_ENTRY_SIZE) {
			pdt_entry_addr |= (page_number << 8);

			retval = synaptics_rmi4_i2c_read(rmi4_data,
					pdt_entry_addr,
					(unsigned char *)&rmi_fd,
					sizeof(rmi_fd));
			if (retval < 0) {
				dev_err(&rmi4_data->i2c_client->dev,
						"%s:synaptics_rmi4_i2c_read Failed\n",
						__func__);

				return retval;
				}

			fhandler = NULL;

			if (rmi_fd.fn_number == 0) {
				dev_dbg(&rmi4_data->i2c_client->dev,
						"%s: Reached end of PDT\n",
						__func__);
				break;
			}

			dev_dbg(&rmi4_data->i2c_client->dev,
					"%s: F%02x found (page %d)\n",
					__func__, rmi_fd.fn_number,
					page_number);

			switch (rmi_fd.fn_number) {
			case SYNAPTICS_RMI4_F01:
				rmi4_data->f01_query_base_addr =
						rmi_fd.query_base_addr;
				rmi4_data->f01_ctrl_base_addr =
						rmi_fd.ctrl_base_addr;
				rmi4_data->f01_data_base_addr =
						rmi_fd.data_base_addr;
				rmi4_data->f01_cmd_base_addr =
						rmi_fd.cmd_base_addr;

				if (synaptics_rmi4_crc_in_progress(rmi4_data, &status))
					goto rescan;

				retval =
				synaptics_rmi4_query_device_info(rmi4_data);
				if (retval < 0)
					return retval;

				if (status.flash_prog == 1) {
					pr_notice("%s: In flash prog mode, status = 0x%02x\n",
							__func__,
							status.status_code);
					goto flash_prog_mode;
				}
				break;

			case SYNAPTICS_RMI4_F11:
				if (rmi_fd.intr_src_count == 0)
					break;

				retval = synaptics_rmi4_alloc_fh(&fhandler,
						&rmi_fd, page_number);
				if (retval < 0) {
					dev_err(&rmi4_data->i2c_client->dev,
							"%s: Failed to alloc for F%d\n",
							__func__,
							rmi_fd.fn_number);
					return retval;
				}

				retval = synaptics_rmi4_f11_init(rmi4_data,
						fhandler, &rmi_fd, intr_count);
				if (retval < 0)
					return retval;
				break;

			case SYNAPTICS_RMI4_F1A:
				if (rmi_fd.intr_src_count == 0)
					break;

				retval = synaptics_rmi4_alloc_fh(&fhandler,
						&rmi_fd, page_number);
				if (retval < 0) {
					dev_err(&rmi4_data->i2c_client->dev,
							"%s: Failed to alloc for F%d\n",
							__func__,
							rmi_fd.fn_number);
					return retval;
				}

				retval = synaptics_rmi4_f1a_init(rmi4_data,
						fhandler, &rmi_fd, intr_count);
				if (retval < 0)
					return retval;
				break;

			case SYNAPTICS_RMI4_F54:
			case SYNAPTICS_RMI4_F55:
				if (rmi_fd.intr_src_count == 0)
					break;

				retval = synaptics_rmi4_alloc_fh(&fhandler,
						&rmi_fd, page_number);
				if (retval < 0) {
					dev_err(&rmi4_data->i2c_client->dev,
							"%s: Failed to alloc for F%d\n",
							__func__,
							rmi_fd.fn_number);
					return retval;
				}
				break;
			case SYNAPTICS_RMI4_F34:
				rmi4_data->f34_query_base_addr = rmi_fd.query_base_addr;
				rmi4_data->f34_ctrl_base_addr = rmi_fd.ctrl_base_addr;
				rmi4_data->f34_data_base_addr = rmi_fd.data_base_addr;
				break;

			default:
				break;
			}

			bootloader_rmi4_data = rmi4_data;

			/* Accumulate the interrupt count */
			intr_count += (rmi_fd.intr_src_count & MASK_3BIT);

			if (fhandler && rmi_fd.intr_src_count) {
				list_add_tail(&fhandler->link,
						&rmi->support_fn_list);
			}
		}
	}
	rmi4_data->num_of_intr_regs = (intr_count + 7) / 8;
	dev_dbg(&rmi4_data->i2c_client->dev,
			"%s: Number of interrupt registers = %d\n",
			__func__, rmi4_data->num_of_intr_regs);

return 0;
flash_prog_mode:

	rmi4_data->num_of_intr_regs = (intr_count + 7) / 8;
	dev_dbg(&rmi4_data->i2c_client->dev,
			"%s: Number of interrupt registers = %d\n",
			__func__, rmi4_data->num_of_intr_regs);

	memset(rmi4_data->intr_mask, 0x00, sizeof(rmi4_data->intr_mask));

	/*
	 * Map out the interrupt bit masks for the interrupt sources
	 * from the registered function handlers.
	 */
	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry(fhandler, &rmi->support_fn_list, link)
			data_sources += fhandler->num_of_data_sources;
	}
	if (data_sources) {
		if (!list_empty(&rmi->support_fn_list)) {
			list_for_each_entry(fhandler,
						&rmi->support_fn_list, link) {
				if (fhandler->num_of_data_sources) {
					rmi4_data->intr_mask[fhandler->intr_reg_num] |=
							fhandler->intr_mask;
				}
			}
		}
	}

	/* Enable the interrupt sources */
	for (ii = 0; ii < rmi4_data->num_of_intr_regs; ii++) {
		if (rmi4_data->intr_mask[ii] != 0x00) {
			dev_dbg(&rmi4_data->i2c_client->dev,
					"%s: Interrupt enable mask %d = 0x%02x\n",
					__func__, ii, rmi4_data->intr_mask[ii]);
			intr_addr = rmi4_data->f01_ctrl_base_addr + 1 + ii;
			retval = synaptics_rmi4_i2c_write(rmi4_data,
					intr_addr,
					&(rmi4_data->intr_mask[ii]),
					sizeof(rmi4_data->intr_mask[ii]));
			if (retval < 0)
				return retval;
		}
	}

	return 0;
}


static int synaptics_rmi4_reset_command(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	int page_number;
	unsigned char command = 0x01;
	unsigned short pdt_entry_addr;
	struct synaptics_rmi4_fn_desc rmi_fd;
	struct synaptics_rmi4_f01_device_status status;
	bool done = false;

rescan:
	/* Scan the page description tables of the pages to service */
	for (page_number = 0; page_number < PAGES_TO_SERVICE; page_number++) {
		for (pdt_entry_addr = PDT_START; pdt_entry_addr > PDT_END;
				pdt_entry_addr -= PDT_ENTRY_SIZE) {
			pdt_entry_addr |= (page_number << 8);

			retval = synaptics_rmi4_i2c_read(rmi4_data,
					pdt_entry_addr,
					(unsigned char *)&rmi_fd,
					sizeof(rmi_fd));
			if (retval < 0)
				return retval;

			if (rmi_fd.fn_number == 0)
				break;

			switch (rmi_fd.fn_number) {
			case SYNAPTICS_RMI4_F01:
				rmi4_data->f01_cmd_base_addr =
						rmi_fd.cmd_base_addr;
				rmi4_data->f01_data_base_addr =
						rmi_fd.data_base_addr;
				if (synaptics_rmi4_crc_in_progress(rmi4_data, &status))
					goto rescan;
				done = true;
				break;
			}
		}
		if (done) {
			dev_info(&rmi4_data->i2c_client->dev,
				"%s: Find F01 in page description table 0x%x\n",
				__func__, rmi4_data->f01_cmd_base_addr);
			break;
		}
	}


	if (!done) {
		dev_err(&rmi4_data->i2c_client->dev,
			"%s: Cannot find F01 in page description table\n",
			__func__);
		return -EINVAL;
	}
	retval = synaptics_rmi4_i2c_write(rmi4_data,
			rmi4_data->f01_cmd_base_addr,
			&command,
			sizeof(command));
	if (retval < 0) {
		dev_err(&rmi4_data->i2c_client->dev,
				"%s: Failed to issue reset command, error = %d\n",
				__func__, retval);
		return retval;
	}

	msleep(rmi4_data->reset_delay_ms);
	return retval;
}

static int synaptics_rmi4_reset_device(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	struct synaptics_rmi4_fn *fhandler, *next_list_entry;
	struct synaptics_rmi4_device_info *rmi;
	struct synaptics_rmi4_exp_fn *exp_fhandler;

	rmi = &(rmi4_data->rmi4_mod_info);

	retval = synaptics_rmi4_reset_command(rmi4_data);
	if (retval < 0) {
		dev_err(&rmi4_data->i2c_client->dev,
				"%s: Failed to send command reset\n",
				__func__);
		return retval;
	}
	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry_safe(fhandler, next_list_entry, &rmi->support_fn_list, link) {
			if (fhandler->fn_number == SYNAPTICS_RMI4_F1A)
				synaptics_rmi4_f1a_kfree(fhandler);
			else
				kfree(fhandler->data);
			if (fhandler) {
				list_del(&fhandler->link);
				kfree(fhandler);
			}
		}
	}

	retval = synaptics_rmi4_query_device(rmi4_data);
	if (retval < 0) {
		dev_err(&rmi4_data->i2c_client->dev,
				"%s: Failed to query device\n",
				__func__);
		return retval;
	}

	mutex_lock(&exp_data.mutex);
	if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link) {
			if (exp_fhandler->fn_type == RMI_F54) {
				exp_fhandler->func_remove(rmi4_data);
				exp_fhandler->func_init(rmi4_data);
			}
		}
	}
	mutex_unlock(&exp_data.mutex);
	return 0;
}

/**
* synaptics_rmi4_detection_work()
*
* Called by the kernel at the scheduled time.
*
* This function is a self-rearming work thread that checks for the
* insertion and removal of other expansion Function modules such as
* rmi_dev and calls their initialization and removal callback functions
* accordingly.
*/
static void synaptics_rmi4_detection_work(struct work_struct *work)
{
	struct synaptics_rmi4_exp_fn *exp_fhandler, *next_list_entry;

	pr_info("%s: enter synaptics_rmi4_detection_work\n", __func__);
	mutex_lock(&exp_data.mutex);

	if (!list_empty(&exp_data.list)) {
		list_for_each_entry_safe(exp_fhandler,
				next_list_entry,
				&exp_data.list,
				link) {
				pr_info("%s: exp_fhandler->fn_type = %d\n", __func__, exp_fhandler->fn_type);
			if ((exp_fhandler->func_init != NULL) &&
					(exp_fhandler->inserted == false)) {
					pr_info("pzh:enter exp_fhandler->func_init\n");
				exp_fhandler->func_init(exp_data.rmi4_data);
				exp_fhandler->inserted = true;
			} else if ((exp_fhandler->func_init == NULL) &&
					(exp_fhandler->inserted == true)) {
				exp_fhandler->func_remove(exp_data.rmi4_data);
				list_del(&exp_fhandler->link);
				kfree(exp_fhandler);
			}
		}
	}
	mutex_unlock(&exp_data.mutex);

	pr_info("%s: leave synaptics_rmi4_detection_work\n", __func__);
}

/**
* synaptics_rmi4_new_function()
*
* Called by other expansion Function modules in their module init and
* module exit functions.
*
* This function is used by other expansion Function modules such as
* rmi_dev to register themselves with the driver by providing their
* initialization and removal callback function pointers so that they
* can be inserted or removed dynamically at module init and exit times,
* respectively.
*/
void synaptics_rmi4_new_function(enum exp_fn fn_type, bool insert,
		int (*func_init)(struct synaptics_rmi4_data *rmi4_data),
		void (*func_remove)(struct synaptics_rmi4_data *rmi4_data),
		void (*func_attn)(struct synaptics_rmi4_data *rmi4_data,
		unsigned char intr_mask))
{
	struct synaptics_rmi4_exp_fn *exp_fhandler;

	if (!exp_data.initialized) {
		mutex_init(&exp_data.mutex);
		INIT_LIST_HEAD(&exp_data.list);
		exp_data.initialized = 1;
	}

	mutex_lock(&exp_data.mutex);
	if (insert) {
		exp_fhandler = kzalloc(sizeof(*exp_fhandler), GFP_KERNEL);
		if (!exp_fhandler)
			goto exit;
		exp_fhandler->fn_type = fn_type;
		exp_fhandler->func_init = func_init;
		exp_fhandler->func_attn = func_attn;
		exp_fhandler->func_remove = func_remove;
		exp_fhandler->inserted = false;
		list_add_tail(&exp_fhandler->link, &exp_data.list);
	} else {
		if (!list_empty(&exp_data.list)) {
				list_for_each_entry(exp_fhandler, &exp_data.list, link) {
					if (exp_fhandler->func_init == func_init) {
						exp_fhandler->inserted = false;
						exp_fhandler->func_init = NULL;
						exp_fhandler->func_attn = NULL;
						goto exit;
					}
			}
		}
	}
exit:
	mutex_unlock(&exp_data.mutex);

	if (exp_data.queue_work) {
		queue_delayed_work(exp_data.workqueue,
				&exp_data.work,
				msecs_to_jiffies(EXP_FN_WORK_DELAY_MS));
	}
}
EXPORT_SYMBOL(synaptics_rmi4_new_function);

/*ergate*/
#define SYN_FW_NAME "PR1101200-s2202_zte_32313032.img"
#define SYNAPTICS_MAX_Y_POSITION	73

static void touchscreen_reset(int hl, unsigned gpio)
{
	gpio_direction_output(gpio, hl);
}

static int detect_device(struct synaptics_rmi4_data *rmi4_data)
{
	int i;
	char buf[1];
	int ret = 0;

	if (rmi4_data == NULL)
		return ret;

	for (i = 0; i < 3; i++) {
		ret = synaptics_rmi4_i2c_read(rmi4_data, 0xFF, buf, 1);
		if (ret >= 0) {
			ret = 1;
			break;
		}
		ret = 0;
		usleep_range(10000, 10500);
	}

	return ret;
}

static int touchscreen_gpio_init(struct device *dev, int flag, char *vreg_vdd, char *vreg_vbus,
unsigned reset_gpio, unsigned irq_gpio)
{
	int ret = -EINVAL;

	if (flag == 1) {
		vdd = vbus = NULL;
		vdd = regulator_get(dev, vreg_vdd);

		if (IS_ERR(vdd)) {
			pr_err("%s get failed\n", vreg_vdd);
			return -EINVAL;
		}
		if (regulator_set_voltage(vdd, 2850000, 2850000)) {
			pr_err("%s set failed\n", vreg_vdd);
			return -EINVAL;
		}

		vbus = regulator_get(dev, vreg_vbus);
		if (IS_ERR(vbus)) {
			pr_err("%s get failed\n", vreg_vbus);
			return -EINVAL;
		}

		if (regulator_set_voltage(vbus, 1800000, 1800000))
			pr_err(" %s set failed\n", vreg_vbus);

		ret = gpio_request(reset_gpio, "touch voltage");
		if (ret) {
			pr_err(" gpio %d request is error!\n", reset_gpio);
			return -EINVAL;
		}

		ret = gpio_request(irq_gpio, "touch voltage");
		if (ret) {
			pr_err("gpio %d request is error!\n", irq_gpio);
			return -EINVAL;
		}
		gpio_direction_output(irq_gpio, 1);
		usleep_range(10000, 10500);
		gpio_direction_input(irq_gpio);

	}

	if (flag == 0) {
		regulator_put(vdd);
		regulator_put(vbus);
		gpio_free(irq_gpio);
		gpio_free(reset_gpio);
	}

	return 0;

}

static void touchscreen_power(int on)
{
	int rc = -EINVAL;

	if (!vdd || !vbus)
		return;

	if (on) {
		rc = regulator_enable(vdd);
		if (rc) {
			pr_err("vdd enable failed\n");
			return;
		}
		rc = regulator_enable(vbus);
		if (rc) {
			pr_err("vbus enable failed\n");
			return;
		}
	} else {
		rc = regulator_disable(vdd);
		if (rc) {
			pr_err("vdd disable failed\n");
			return;
		}
		rc = regulator_disable(vbus);
		if (rc) {
			pr_err("vbus disable failed\n");
			return;
		}
	}
}
#ifdef CONFIG_OF
static unsigned char TM_SAMPLE3_f1a_button_codes[] = {KEY_BACK, KEY_HOME, KEY_MENU};
static struct synaptics_dsx_cap_button_map TM_SAMPLE3_cap_button_map = {
	.nbuttons = ARRAY_SIZE(TM_SAMPLE3_f1a_button_codes),
	.map = TM_SAMPLE3_f1a_button_codes,
};

static int syna_parse_dt(struct device *dev, struct synaptics_dsx_platform_data *pdata)
{
	int rc;

	pdata->irq_gpio			= of_get_named_gpio(pdata->client->dev.of_node,
		"synaptics,irq-gpio", 0);
	pdata->reset_delay_ms	= 100;
	pdata->reset_gpio		= of_get_named_gpio(pdata->client->dev.of_node,
		"synaptics,reset-gpio", 0);
	pdata->vdd				= VREG_VDD;
	pdata->vbus				= VREG_VBUS;
	pdata->irq_flags		= IRQF_TRIGGER_LOW;
	pdata->x_flip			= 0;
	pdata->y_flip			= 0;
	pdata->cap_button_map	= &TM_SAMPLE3_cap_button_map;
	rc = of_property_read_u32(dev->of_node, "synaptics,max_y", &pdata->maxy_offset);
	if (rc) {
		dev_err(dev, "Failed to read display max x\n");
		return -EINVAL;
	}
	pr_info("maxy_offset:%d\n", pdata->maxy_offset);
	return 0;
}
#endif
#if defined(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_V10)
int syna_update_flag;
extern int syna_get_fw_ver(struct i2c_client *client, char *pfwfile);
extern int fwu_start_reflash(void);

extern int syna_fwupdate_init(struct i2c_client *client);
extern int rmi4_fw_update_module_init(void);
extern int syna_fwupdate_deinit(struct i2c_client *client);
#endif
extern char *syna_file_name;
#if defined(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_TEST_REPORTING_V10)
extern int rmi4_f54_module_init(void);
#endif

#if defined(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_RMI_DEV_V10)
extern int rmidev_module_init(void);
#endif

static int synaptics_rmi4_check_status(struct synaptics_rmi4_data *rmi4_data,
		bool *was_in_bl_mode)
{
	int retval;
	int timeout = CHECK_STATUS_TIMEOUT_MS;
	unsigned char intr_status;
	struct synaptics_rmi4_f01_device_status status;

	pr_info("pzh:Enter synaptics_rmi4_check_status\n");

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			rmi4_data->f01_data_base_addr,
			status.data,
			sizeof(status.data));
	if (retval < 0)
		return retval;

	while (status.status_code == STATUS_CRC_IN_PROGRESS) {
		if (timeout > 0)
			msleep(20);
		else
			return -EINVAL;

		retval = synaptics_rmi4_i2c_read(rmi4_data,
				rmi4_data->f01_data_base_addr,
				status.data,
				sizeof(status.data));
		if (retval < 0)
			return retval;

		timeout -= 20;
	}

	if (timeout != CHECK_STATUS_TIMEOUT_MS)
		*was_in_bl_mode = true;

	if (status.flash_prog == 1) {
		rmi4_data->flash_prog_mode = true;
		pr_notice("%s: In flash prog mode, status = 0x%02x\n",
				__func__,
				status.status_code);
	} else {
		rmi4_data->flash_prog_mode = false;
	}

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			rmi4_data->f01_data_base_addr + 1,
			&intr_status,
			sizeof(intr_status));
	if (retval < 0) {
		pr_info("%s: Failed to read interrupt status\n", __func__);
		return retval;
	}

	return 0;
}



static void synaptics_get_configid(
	struct synaptics_rmi4_data *ts,
	char *p_chip_type,
	char *p_sensor,
	int *p_fw_ver)
{
	int ret;
	int retval;
	bool was_in_bl_mode;
	char chip_type;
	char sensor_id;

	if (!ts || !bootloader_rmi4_data)
		return;

	retval = synaptics_rmi4_check_status(ts, &was_in_bl_mode);
	if (retval < 0)
		pr_info("%s:Failed to check status\n", __func__);

	if (was_in_bl_mode && ts->flash_prog_mode) {
		pr_info("%s: now in bootloader mode\n", __func__);
		retval = synaptics_rmi4_i2c_read(ts,
			bootloader_rmi4_data->f01_query_base_addr + 3,
			&chip_type, sizeof(chip_type));
		if (retval < 0) {
			pr_info("%s:synaptics_rmi4_reg_read_chip_type error\n", __func__);
			return;
		}
		ts->config_id.chip_type = chip_type;
		pr_info("%s:ts->config_id.chip_type=%d", __func__, ts->config_id.chip_type);

		retval = synaptics_rmi4_i2c_read(ts,
			bootloader_rmi4_data->f01_query_base_addr + 2,
			&sensor_id, sizeof(sensor_id));
		if (retval < 0) {
			pr_info("%s:synaptics_rmi4_reg_read_sensor_id error\n", __func__);
			return;
		}
		ts->config_id.sensor = sensor_id;
		pr_info("%s:ts->config_id.sensor = %d", __func__, ts->config_id.sensor);

		pr_info("chip_type = 0x%x, sensor = 0x%x\n",
			ts->config_id.chip_type,
			ts->config_id.sensor);

		if (!p_chip_type || !p_sensor)
			return;
pr_info("syna---444\n");

		switch (ts->config_id.chip_type) {
		case 31:
			ts->config_id.chip_type = 49;
			snprintf(p_chip_type, PAGE_SIZE, "S2200(0x%x)", ts->config_id.chip_type);
			break;
		case 32:
			ts->config_id.chip_type = 50;
			snprintf(p_chip_type, PAGE_SIZE, "S2202(0x%x)", ts->config_id.chip_type);
			break;
		case 33:
			ts->config_id.chip_type = 51;
			snprintf(p_chip_type, PAGE_SIZE, "S3200(0x%x)", ts->config_id.chip_type);
			break;
		case 34:
			ts->config_id.chip_type = 52;
			snprintf(p_chip_type, PAGE_SIZE, "S3202(0x%x)", ts->config_id.chip_type);
			break;
		case 35:
			ts->config_id.chip_type = 53;
			snprintf(p_chip_type, PAGE_SIZE, "S3203(0x%x)", ts->config_id.chip_type);
			break;
		case 36:
			ts->config_id.chip_type = 54;
			snprintf(p_chip_type, PAGE_SIZE, "S7020(0x%x)", ts->config_id.chip_type);
			break;
		case 37:
			ts->config_id.chip_type = 55;
			snprintf(p_chip_type, PAGE_SIZE, "S7300(0x%x)", ts->config_id.chip_type);
			break;
		case 44:
			ts->config_id.chip_type = 68;
			snprintf(p_chip_type, PAGE_SIZE, "S2331(0x%x)", ts->config_id.chip_type);
			break;
		case 51:
			ts->config_id.chip_type = 81;
			snprintf(p_chip_type, PAGE_SIZE, "S7040(0x%x)", ts->config_id.chip_type);
			break;
		case 52:
			ts->config_id.chip_type = 82;
			snprintf(p_chip_type, PAGE_SIZE, "S7060(0x%x)", ts->config_id.chip_type);
			break;
		default:
			snprintf(p_chip_type, PAGE_SIZE, "unknown(0x%x)", ts->config_id.chip_type);
			break;
		}

		switch (ts->config_id.sensor) {
		case 31:
			ts->config_id.sensor = 49;
			snprintf(p_sensor, PAGE_SIZE, "TPK(0x%x)", ts->config_id.sensor);
			touch_moudle = TPK_MOUDLE;
			break;
		case 32:
			ts->config_id.sensor = 50;
			snprintf(p_sensor, PAGE_SIZE, "Truly(0x%x)", ts->config_id.sensor);
			touch_moudle = TRULY_MOUDLE;
			break;
		case 33:
			ts->config_id.sensor = 51;
			snprintf(p_sensor, PAGE_SIZE, "Success(0x%x)", ts->config_id.sensor);
			touch_moudle = SUCCESS_MOUDLE;
			break;
		case 34:
			ts->config_id.sensor = 52;
			snprintf(p_sensor, PAGE_SIZE, "Ofilm(0x%x)", ts->config_id.sensor);
			touch_moudle = OFILM_MOUDLE;
			break;
		case 35:
			ts->config_id.sensor = 53;
			snprintf(p_sensor, PAGE_SIZE, "Lead(0x%x)", ts->config_id.sensor);
			touch_moudle = LEAD_MOUDLE;
			break;
		case 36:
			ts->config_id.sensor = 54;
			snprintf(p_sensor, PAGE_SIZE, "Wintek(0x%x)", ts->config_id.sensor);
			touch_moudle = WINTEK_MOUDLE;
			break;
		case 37:
			ts->config_id.sensor = 55;
			snprintf(p_sensor, PAGE_SIZE, "Laibao(0x%x)", ts->config_id.sensor);
			touch_moudle = LAIBAO_MOUDLE;
			break;
		case 38:
			ts->config_id.sensor = 56;
			snprintf(p_sensor, PAGE_SIZE, "CMI(0x%x)", ts->config_id.sensor);
			touch_moudle = CMI_MOUDLE;
			break;
		case 39:
			ts->config_id.sensor = 57;
			snprintf(p_sensor, PAGE_SIZE, "ECW(0x%x)", ts->config_id.sensor);
			touch_moudle = ECW_MOUDLE;
			break;
		case 41:
			ts->config_id.sensor = 65;
			snprintf(p_sensor, PAGE_SIZE, "Goworld(0x%x)", ts->config_id.sensor);
			touch_moudle = GOWORLD_MOUDLE;
			break;
		case 42:
			ts->config_id.sensor = 66;
			snprintf(p_sensor, PAGE_SIZE, "Baoming(0x%x)", ts->config_id.sensor);
			touch_moudle = BAOMING_MOUDLE;
			break;
		case 43:
			ts->config_id.sensor = 67;
			snprintf(p_sensor, PAGE_SIZE, "Eachopto(0x%x)", ts->config_id.sensor);
			touch_moudle = EACHOPTO_MOUDLE;
			break;
		case 45:
			ts->config_id.sensor = 69;
			snprintf(p_sensor, PAGE_SIZE, "JUNDA(0x%x)", ts->config_id.sensor);
			touch_moudle = JUNDA_MOUDLE;
			break;
		case 50:
			ts->config_id.sensor = 80;
			snprintf(p_sensor, PAGE_SIZE, "LCE(0x%x)", ts->config_id.sensor);
			touch_moudle = LCE_MOUDLE;
			break;
		default:
			snprintf(p_sensor, PAGE_SIZE, "unknown(0x%x)", ts->config_id.sensor);
			touch_moudle = UNKNOWN_MOUDLE;
			break;
		}
	} else{
		ret = synaptics_rmi4_i2c_read(ts, ts->f34_ctrl_base_addr, (char *)&ts->config_id, 4);
		pr_info("%s:ts->f34_ctrl_base_addr == 0x%x", __func__, ts->f34_ctrl_base_addr);
		if (ret < 0)
			pr_err("%s: failed to get ts f34.ctrl_base\n", __func__);

		pr_info("chip_type = 0x%x, sensor = 0x%x, fw_ver = 0x%x\n",
			ts->config_id.chip_type,
			ts->config_id.sensor,
			ts->config_id.fw_ver);

		if (!p_chip_type || !p_sensor || !p_fw_ver)
			return;

		switch (ts->config_id.chip_type) {
		case '1':
			snprintf(p_chip_type, PAGE_SIZE, "S2200(0x%x)", ts->config_id.chip_type);
			break;
		case '2':
			snprintf(p_chip_type, PAGE_SIZE, "S2202(0x%x)", ts->config_id.chip_type);
			break;
		case '3':
			snprintf(p_chip_type, PAGE_SIZE, "S3200(0x%x)", ts->config_id.chip_type);
			break;
		case '4':
			snprintf(p_chip_type, PAGE_SIZE, "S3202(0x%x)", ts->config_id.chip_type);
			break;
		case '5':
			snprintf(p_chip_type, PAGE_SIZE, "S3203(0x%x)", ts->config_id.chip_type);
			break;
		case '6':
			snprintf(p_chip_type, PAGE_SIZE, "S7020(0x%x)", ts->config_id.chip_type);
			break;
		case '7':
			snprintf(p_chip_type, PAGE_SIZE, "S7300(0x%x)", ts->config_id.chip_type);
			break;
		case 'D':
			snprintf(p_chip_type, PAGE_SIZE, "S2331(0x%x)", ts->config_id.chip_type);
			break;
		case 'Q':
			snprintf(p_chip_type, PAGE_SIZE, "S7040(0x%x)", ts->config_id.chip_type);
			break;
		case 'R':
			snprintf(p_chip_type, PAGE_SIZE, "S7060(0x%x)", ts->config_id.chip_type);
			break;
		default:
			snprintf(p_chip_type, PAGE_SIZE, "unknown(0x%x)", ts->config_id.chip_type);
			break;
		}

		switch (ts->config_id.sensor) {
		case '1':
			snprintf(p_sensor, PAGE_SIZE, "TPK(0x%x)", ts->config_id.sensor);
			touch_moudle = TPK_MOUDLE;
			break;
		case '2':
			snprintf(p_sensor, PAGE_SIZE, "Truly(0x%x)", ts->config_id.sensor);
			touch_moudle = TRULY_MOUDLE;
			break;
		case '3':
			snprintf(p_sensor, PAGE_SIZE, "Success(0x%x)", ts->config_id.sensor);
			touch_moudle = SUCCESS_MOUDLE;
			break;
		case '4':
			snprintf(p_sensor, PAGE_SIZE, "Ofilm(0x%x)", ts->config_id.sensor);
			touch_moudle = OFILM_MOUDLE;
			break;
		case '5':
			snprintf(p_sensor, PAGE_SIZE, "Lead(0x%x)", ts->config_id.sensor);
			touch_moudle = LEAD_MOUDLE;
			break;
		case '6':
			snprintf(p_sensor, PAGE_SIZE, "Wintek(0x%x)", ts->config_id.sensor);
			touch_moudle = WINTEK_MOUDLE;
			break;
		case '7':
			snprintf(p_sensor, PAGE_SIZE, "Laibao(0x%x)", ts->config_id.sensor);
			touch_moudle = LAIBAO_MOUDLE;
			break;
		case '8':
			snprintf(p_sensor, PAGE_SIZE, "CMI(0x%x)", ts->config_id.sensor);
			touch_moudle = CMI_MOUDLE;
			break;
		case '9':
			snprintf(p_sensor, PAGE_SIZE, "ECW(0x%x)", ts->config_id.sensor);
			touch_moudle = ECW_MOUDLE;
			break;
		case 'A':
			snprintf(p_sensor, PAGE_SIZE, "Goworld(0x%x)", ts->config_id.sensor);
			touch_moudle = GOWORLD_MOUDLE;
			break;
		case 'B':
			snprintf(p_sensor, PAGE_SIZE, "Baoming(0x%x)", ts->config_id.sensor);
			touch_moudle = BAOMING_MOUDLE;
			break;
		case 'C':
			snprintf(p_sensor, PAGE_SIZE, "Eachopto(0x%x)", ts->config_id.sensor);
			touch_moudle = EACHOPTO_MOUDLE;
			break;
		case 'E':
			snprintf(p_sensor, PAGE_SIZE, "JUNDA(0x%x)", ts->config_id.sensor);
			touch_moudle = JUNDA_MOUDLE;
			break;
		case 'P':
			snprintf(p_sensor, PAGE_SIZE, "LCE(0x%x)", ts->config_id.sensor);
			touch_moudle = LCE_MOUDLE;
			break;
		default:
			snprintf(p_sensor, PAGE_SIZE, "unknown(0x%x)", ts->config_id.sensor);
			touch_moudle = UNKNOWN_MOUDLE;
			break;
		}

		*p_fw_ver = ts->config_id.fw_ver;
	}

	if (touch_moudle < SYN_MOUDLE_NUM_MAX) {
		syna_file_name = syn_fwfile_table[touch_moudle];
		pr_info("%s: syna_file_name = %s\n", __func__, syna_file_name);
	}
	pr_info("chip: %s, sensor %s, fw 0x%x\n", p_chip_type, p_sensor, *p_fw_ver);
}

ssize_t
proc_read_val(struct file *file, char __user *page, size_t size, loff_t *ppos)

{
	int len = 0;
	char chiptype[16], sensor[16];
	int fw_ver = 0;
	int ready_fw_ver = -1;
	int fw_flag = 0;
	int fw_version = 0;

	if (syn_ts == NULL)
		return -EINVAL;
	if (*ppos)
		return 0;

	len += snprintf(page + len,  PAGE_SIZE, "Manufacturer : %s\n", "Synaptics");

	synaptics_get_configid(syn_ts, (char *)&chiptype, (char *)&sensor, &fw_ver);
	fw_version = ((fw_ver & 0x000000ff) << 8) | ((fw_ver & 0x0000ff00) >> 8);
#if defined(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_V10)
	if (touch_moudle < SYN_MOUDLE_NUM_MAX)
		ready_fw_ver = syna_get_fw_ver(syn_ts->i2c_client, syn_fwfile_table[touch_moudle]);
#endif
	len += snprintf(page + len,  PAGE_SIZE, "chip type : %s\n", chiptype);
	len += snprintf(page + len,  PAGE_SIZE, "sensor partner : %s\n", sensor);
	len += snprintf(page + len,  PAGE_SIZE, "FW Revision : %c%c\n",
		(fw_version & 0x0000ff00) >> 8, fw_version & 0x0000ff);
#ifdef CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_V10
	len += snprintf(page + len,  PAGE_SIZE, "update flag : 0x%02x\n", syna_update_flag);
#endif
	if (ready_fw_ver > 0) {
		len += snprintf(page + len,  PAGE_SIZE, "need update : %s\n",
			(ready_fw_ver > fw_version ? "yes" : "no"));
		len += snprintf(page + len,  PAGE_SIZE, "ready fw version : %c%c\n",
			(ready_fw_ver & 0x0000ff00) >> 8, ready_fw_ver & 0x000000ff);
	} else {
		len += snprintf(page + len,  PAGE_SIZE, "need update : %s\n", "no");
		len += snprintf(page + len,  PAGE_SIZE, "ready fw version : %s\n", "null");
	}

	if (ready_fw_ver == -1)
		fw_flag = 2;
	else if (ready_fw_ver == fw_version)
		fw_flag = 0;
	else if (ready_fw_ver > fw_version)
		fw_flag = 1;
	else if (ready_fw_ver < fw_version)
		fw_flag = 2;

	len += snprintf(page + len,  PAGE_SIZE, "FW flag : 0x%02x\n", fw_flag);

	*ppos += len;

	return len;
}

ssize_t proc_write_val(struct file *file, const char  __user *buffer,
		   size_t count, loff_t *off)

{
	unsigned long val, ret;

	ret = copy_from_user(&val, buffer, 1);

#if defined(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_V10)
	syna_update_flag = 0;
	if (touch_moudle >= SYN_MOUDLE_NUM_MAX) {
		pr_info("touchscreen moudle unknown!");
		syna_update_flag = 3;
		return -EINVAL;
	}
	syna_update_flag = 1;
	/*disable_irq(syn_ts->i2c_client->irq);*/
	if (fwu_start_reflash()) {
		enable_irq(syn_ts->i2c_client->irq);
		syna_update_flag = 3;
		pr_info("syna fw update fail!\n");
		return -EINVAL;
	}

	/*enable_irq(syn_ts->i2c_client->irq);*/

	syna_update_flag = 2;
	pr_info("syna fw update Ok!\n");
#endif

	return -EINVAL;
}
static ssize_t
ts_update_read_val(struct file *file, char __user *page, size_t size, loff_t *ppos)
{
	int len = 1;

	pr_info("%s:---enter---\n", __func__);
	if (*ppos) {
		/*pr_info("[HEAD]wr: %d", cmd_head.wr);*/
		pr_info("[PARAM]size: %d, *ppos: %d", (int)size, (int)*ppos);
		pr_info("[TOOL_READ]ADB call again, return it.");
		return 0;
	}
	*ppos += len;
#if defined(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_V10)
		syna_update_flag = 0;
		if (touch_moudle >= SYN_MOUDLE_NUM_MAX) {
			pr_info("touchscreen moudle unknown!");
			syna_update_flag = 3;
			return 1;
		}
		syna_update_flag = 1;
		/*disable_irq(syn_ts->i2c_client->irq);*/
		if (fwu_start_reflash()) {
			/*enable_irq(syn_ts->i2c_client->irq);*/
			syna_update_flag = 3;
			pr_info("syna fw update fail!\n");
			return 1;
		}

		/*enable_irq(syn_ts->i2c_client->irq);*/

		syna_update_flag = 2;
		pr_info("syna fw update Ok!\n");
#endif

	return len;
}

static int get_max_std_rawdata(short *max_rawdata)
{
	short rawdata0[] = SYN_TPK_RAW_DATA_MAX;
	short rawdata1[] = SYN_TRULY_RAW_DATA_MAX;
	short rawdata2[] = SYN_SUCCESS_RAW_DATA_MAX;
	short rawdata3[] = SYN_OFILM_RAW_DATA_MAX;
	short rawdata4[] = SYN_LEAD_RAW_DATA_MAX;
	short rawdata5[] = SYN_WINTEK_RAW_DATA_MAX;
	short rawdata6[] = SYN_LAIBAO_RAW_DATA_MAX;
	short rawdata7[] = SYN_CMI_RAW_DATA_MAX;
	short rawdata8[] = SYN_ECW_RAW_DATA_MAX;
	short rawdata9[] = SYN_GOWORLD_RAW_DATA_MAX;
	short rawdata10[] = SYN_BAOMING_RAW_DATA_MAX;
	short rawdata11[] = SYN_JUNDA_RAW_DATA_MAX;
	short rawdata12[] = SYN_JIAGUAN_RAW_DATA_MAX;
	short rawdata13[] = SYN_MUDONG_RAW_DATA_MAX;
	short rawdata14[] = SYN_EACHOPTO_RAW_DATA_MAX;
	short rawdata15[] = SYN_LCE_RAW_DATA_MAX;
	short *rawdata[] = {
		rawdata0, rawdata1, rawdata2, rawdata3, rawdata4, rawdata5,
		rawdata6, rawdata7, rawdata8, rawdata9, rawdata10, rawdata11,
		rawdata12, rawdata13, rawdata14, rawdata15
	};

	short rawdata_lens[] = {
		RAWDATA_LEN(rawdata0),
		RAWDATA_LEN(rawdata1),
		RAWDATA_LEN(rawdata2),
		RAWDATA_LEN(rawdata3),
		RAWDATA_LEN(rawdata4),
		RAWDATA_LEN(rawdata5),
		RAWDATA_LEN(rawdata6),
		RAWDATA_LEN(rawdata7),
		RAWDATA_LEN(rawdata8),
		RAWDATA_LEN(rawdata9),
		RAWDATA_LEN(rawdata10),
		RAWDATA_LEN(rawdata11),
		RAWDATA_LEN(rawdata12),
		RAWDATA_LEN(rawdata13),
		RAWDATA_LEN(rawdata14),
		RAWDATA_LEN(rawdata15)
	};

	if (rawdata_lens[touch_moudle] != num_of_rx * num_of_tx * sizeof(short)) {
		pr_info("%s: array length is not valid\n", __func__);
		return -EINVAL;
	}

	memset(max_rawdata, 0, rawdata_lens[touch_moudle]);
	mutex_lock(&exp_data.mutex);
	memcpy(max_rawdata, rawdata[touch_moudle], rawdata_lens[touch_moudle]);
	mutex_unlock(&exp_data.mutex);

	pr_info("%s: max_rawdata = %d, len = %d\n",
		__func__, (int)sizeof(max_rawdata), (int)rawdata_lens[touch_moudle]);

	return 0;
}

static int get_min_std_rawdata(short *min_rawdata)
{
	short rawdata0[] = SYN_TPK_RAW_DATA_MIN;
	short rawdata1[] = SYN_TRULY_RAW_DATA_MIN;
	short rawdata2[] = SYN_SUCCESS_RAW_DATA_MIN;
	short rawdata3[] = SYN_OFILM_RAW_DATA_MIN;
	short rawdata4[] = SYN_LEAD_RAW_DATA_MIN;
	short rawdata5[] = SYN_WINTEK_RAW_DATA_MIN;
	short rawdata6[] = SYN_LAIBAO_RAW_DATA_MIN;
	short rawdata7[] = SYN_CMI_RAW_DATA_MIN;
	short rawdata8[] = SYN_ECW_RAW_DATA_MIN;
	short rawdata9[] = SYN_GOWORLD_RAW_DATA_MIN;
	short rawdata10[] = SYN_BAOMING_RAW_DATA_MIN;
	short rawdata11[] = SYN_JUNDA_RAW_DATA_MIN;
	short rawdata12[] = SYN_JIAGUAN_RAW_DATA_MIN;
	short rawdata13[] = SYN_MUDONG_RAW_DATA_MIN;
	short rawdata14[] = SYN_EACHOPTO_RAW_DATA_MIN;
	short rawdata15[] = SYN_LCE_RAW_DATA_MIN;
	short *rawdata[] = {
		rawdata0, rawdata1, rawdata2, rawdata3, rawdata4, rawdata5,
		rawdata6, rawdata7, rawdata8, rawdata9, rawdata10, rawdata11,
		rawdata12, rawdata13, rawdata14, rawdata15
	};

	short rawdata_lens[] = {
		RAWDATA_LEN(rawdata0),
		RAWDATA_LEN(rawdata1),
		RAWDATA_LEN(rawdata2),
		RAWDATA_LEN(rawdata3),
		RAWDATA_LEN(rawdata4),
		RAWDATA_LEN(rawdata5),
		RAWDATA_LEN(rawdata6),
		RAWDATA_LEN(rawdata7),
		RAWDATA_LEN(rawdata8),
		RAWDATA_LEN(rawdata9),
		RAWDATA_LEN(rawdata10),
		RAWDATA_LEN(rawdata11),
		RAWDATA_LEN(rawdata12),
		RAWDATA_LEN(rawdata13),
		RAWDATA_LEN(rawdata14),
		RAWDATA_LEN(rawdata15)
	};

	if (rawdata_lens[touch_moudle] != num_of_rx * num_of_tx * sizeof(short)) {
		pr_info("%s: array length is not valid\n", __func__);
		return -EINVAL;
	}

	memset(min_rawdata, 0, rawdata_lens[touch_moudle]);
	mutex_lock(&exp_data.mutex);
	memcpy(min_rawdata, rawdata[touch_moudle], rawdata_lens[touch_moudle]);
	mutex_unlock(&exp_data.mutex);

	pr_info("%s: min_rawdata = %d, len = %d\n",
		__func__, (int)sizeof(min_rawdata),
		(int)rawdata_lens[touch_moudle]);

	return 0;
}

static ssize_t
ts_rawdata_test_val(struct file *file, char __user *page, size_t size, loff_t *ppos)
{
	int ii;
	int len = 0;
	int retval = 0;
	int count = 20;
	char test_result = 0;
	int report_type = 3;
	short *max_rawdata;
	short *min_rawdata;
	short *report_data_16;

	if (*ppos)
		return 0;

	if (!f54 || !syn_ts)
		goto exit;

	max_rawdata = kzalloc(num_of_rx * num_of_tx * sizeof(short), GFP_KERNEL);
	if (!max_rawdata)
		goto exit;

	min_rawdata = kzalloc(num_of_rx * num_of_tx * sizeof(short), GFP_KERNEL);
	if (!min_rawdata)
		goto exit;

	retval = get_max_std_rawdata(max_rawdata);
	if (retval < 0) {
		pr_info("%s: faile to get max std rawdata\n", __func__);
		goto exit;
	}

	retval = get_min_std_rawdata(min_rawdata);
	if (retval < 0) {
		pr_info("%s: faile to get min std rawdata\n", __func__);
		goto exit;
	}

	retval = synaptics_rmi4_raw_data_config(report_type);
	if (retval < 0) {
		pr_info("%s: fail to get raw data\n", __func__);
		goto exit;
	}

	while (!rawdata_flag) {
		usleep_range(10000, 10500);
		count--;
	}

	if (!f54->report_data)
		goto exit;

	report_data_16 = (short *)f54->report_data;

	/*compare*/
	for (ii = 0; ii < num_of_rx * num_of_tx; ii++) {
		if (*(max_rawdata + ii) < *(report_data_16 + ii)) {
			pr_info("%s: test fail! index = %d, max_rawdata = %d, *report_data_16 = %d\n",
				__func__, ii, *(max_rawdata + ii), *(report_data_16 + ii));
			goto exit;
		}
		if (*(min_rawdata + ii) > *(report_data_16 + ii)) {
			pr_info("%s: test fail! index = %d, min_rawdata = %d, *report_data_16 = %d\n",
				__func__, ii, *(min_rawdata + ii), *(report_data_16 + ii));
			goto exit;
		}
	}

	test_result = 1;

exit:
	retval = synaptics_rmi4_reset_device(syn_ts);
	if (retval < 0)
		pr_info("%s: fail to reset device\n", __func__);

	len += snprintf(page + len,  PAGE_SIZE, "%d\n", test_result);

	*ppos += len;

	kfree(max_rawdata);
	max_rawdata = NULL;

	kfree(min_rawdata);
	min_rawdata = NULL;

	return len;
}

static ssize_t
ts_rawdata_read_val(struct file *file, char __user *page, size_t size, loff_t *ppos)
{
	int ii;
	int jj;
	int len = 0;
	int retval = 0;
	int count = 20;
	int report_type = 3;
	short *report_data_16;

	if (*ppos)
		return 0;

	if (!f54 || !syn_ts)
		return -EINVAL;

	retval = synaptics_rmi4_raw_data_config(report_type);
	if (retval < 0) {
		pr_info("%s: faile to get raw data\n", __func__);
		goto exit;
	}

	while (!rawdata_flag) {
		usleep_range(10000, 10500);
		count--;
	}

	if (!f54->report_data)
		goto exit;

	report_data_16 = (short *)f54->report_data;

	/*print*/
	len += snprintf(page + len,  PAGE_SIZE, "   ");
	for (ii = 0; ii < num_of_rx; ii++)
		len += snprintf(page + len,  PAGE_SIZE, "	 %2d", ii);
	len += snprintf(page + len,  PAGE_SIZE, "\n");

	for (ii = 0; ii < num_of_tx; ii++) {
		len += snprintf(page + len,  PAGE_SIZE, "%2d ", ii);
		for (jj = 0; jj < num_of_rx; jj++)
			len += snprintf(page + len,  PAGE_SIZE, "  %5d", *(report_data_16 + ii * num_of_rx + jj));
		len += snprintf(page + len,  PAGE_SIZE, "\n");
	}

exit:
	retval = synaptics_rmi4_reset_device(syn_ts);
	if (retval < 0)
		pr_info("%s: fail to reset device\n", __func__);

	if (len == 0)
		len = 1;

	*ppos += len;

	return len;
}

static int rx_to_rx_test(int report_type)
{
	int ii;
	int jj;
	int retval = 0;
	int count = 20;
	char test_result = 0;
	short *report_data_16;
	short report_data_tmp;
	unsigned char num_min;

	if (!f54 || !syn_ts)
		return -EINVAL;

	retval = synaptics_rmi4_raw_data_config(report_type);
	if (retval < 0) {
		pr_info("%s: faile to get raw data\n", __func__);
		goto exit;
	}

	while (!rawdata_flag) {
		usleep_range(10000, 10500);
		count--;
	}

	if (!f54->report_data)
		goto exit;

	report_data_16 = (short *)f54->report_data;

	/*print*/
	pr_info("   ");
	for (ii = 0; ii < num_of_rx; ii++)
		pr_info("	 %2d", ii);
	pr_info("\n");
	for (ii = 0; ii < num_of_tx; ii++) {
		pr_info("%2d  ", ii);
		for (jj = 0; jj < num_of_rx; jj++)
			pr_info("  %5d", *(report_data_16 + ii * num_of_rx + jj));
		pr_info("\n");
	}

	/*compare*/
	if (report_type == 7) {
		if (num_of_rx <= num_of_tx)
			num_min = num_of_rx;
		else
			num_min = num_of_tx;

		for (ii = 0; ii < num_min; ii++) {
			report_data_tmp = *(report_data_16 + ii * num_of_rx + ii);
			pr_info("%s: value[%d] = %d\n", __func__, ii, report_data_tmp);
			if (report_data_tmp > MAX_RX_TO_RX)
				goto exit;
			if (report_data_tmp < MIN_RX_TO_RX)
				goto exit;
		}
	} else if (report_type == 17) {
		if (num_of_rx > num_of_tx) {
			for (ii = 0; ii < (num_of_rx - num_of_tx); ii++) {
				report_data_tmp = *(report_data_16 + ii * num_of_rx + (ii + num_of_tx));
				pr_info("%s: value[%d] = %d\n", __func__, ii + num_of_tx, report_data_tmp);
				if (report_data_tmp > MAX_RX_TO_RX)
					goto exit;
				if (report_data_tmp < MIN_RX_TO_RX)
					goto exit;
			}
		} else
			goto exit;
	}

	test_result = 1;

exit:
	retval = synaptics_rmi4_reset_device(syn_ts);
	if (retval < 0)
		pr_info("%s: fail to reset device\n", __func__);

	if (test_result == 0)
		pr_info("%s: test failed!\n", __func__);

	return test_result;
}

static int tx_to_tx_test(int report_type)
{
	int ii;
	int retval = 0;
	int count = 20;
	char test_result = 0;
	int report_size = (num_of_tx + 7) / 8;
	char *report_data_8;

	if (!f54 || !syn_ts)
		return -EINVAL;

	retval = synaptics_rmi4_raw_data_config(report_type);
	if (retval < 0) {
		pr_info("%s: faile to get raw data\n", __func__);
		goto exit;
	}

	while (!rawdata_flag) {
		usleep_range(10000, 10500);
		count--;
	}

	if (!f54->report_data)
		goto exit;

	report_data_8 = f54->report_data;

	/*compare*/
	for (ii = 0; ii < report_size; ii++) {
		pr_info("%s: data[%d] = 0x%02x\n", __func__, ii, *(report_data_8 + ii));
		if (ii == (report_size - 1)) {
			if ((*(report_data_8 + ii) << (8 - num_of_tx % 8)) != 0x00)
				goto exit;
		} else {
			if (*(report_data_8 + ii) != 0x00)
				goto exit;
		}
	}

	test_result = 1;

exit:
	retval = synaptics_rmi4_reset_device(syn_ts);
	if (retval < 0)
		pr_info("%s: fail to reset device\n", __func__);

	if (test_result == 0)
		pr_info("%s: test failed!\n", __func__);

	return test_result;
}

static ssize_t
ts_short_circuit_test_val(struct file *file, char __user *page, size_t size, loff_t *ppos)
{
	int len = 0;
	char test_result = 0;

	if (*ppos)
		return 0;

	if (!f54 || !syn_ts)
		return -EINVAL;

	test_result = rx_to_rx_test(F54_RX_TO_RX1);
	if (test_result == 0)
		goto exit;
	if (num_of_rx > num_of_tx) {
		test_result = rx_to_rx_test(F54_RX_TO_RX2);
		if (test_result == 0)
			goto exit;
	}

	test_result = tx_to_tx_test(F54_TX_TO_TX_SHORT);

exit:
	len += snprintf(page + len,  PAGE_SIZE, "%d\n", test_result);

	*ppos += len;

	return len;
}

static const struct file_operations update_proc_ops = {
	.owner = THIS_MODULE,
	.read = ts_update_read_val,
};

static const struct file_operations proc_ops = {
	.owner = THIS_MODULE,
	.read = proc_read_val,
	.write = proc_write_val,
};

static const struct file_operations rawdata_read_proc_ops = {
	.owner = THIS_MODULE,
	.read = ts_rawdata_read_val,
};

static const struct file_operations rawdata_test_proc_ops = {
	.owner = THIS_MODULE,
	.read = ts_rawdata_test_val,
};

static const struct file_operations short_circuit_test_proc_ops = {
	.owner = THIS_MODULE,
	.read = ts_short_circuit_test_val,
};

void zte_synaptics_change_fw_config(struct synaptics_rmi4_data *ts)
{
#ifdef CONFIG_BOARD_WARP4
	uint8_t success_data0[1] = {0x0};

	if (ts->config_id.sensor == 0x39) {
		int retval = 0;

		pr_info("%s: xym, change the ecw fw config!\n", __func__);

		retval = synaptics_rmi4_i2c_write(ts, 0x78, success_data0, 1);
		if (retval < 0)
			dev_err(&(ts->input_dev->dev),
				"%s: Failed to write 4D\n",
				__func__);

	}
#elif defined CONFIG_BOARD_MAX
	int ret = 0;
	uint8_t tpk_data[16] = {0x80, 0x80, 0x80, 0x60, 0x60, 0x60, 0x60, 0x60,
		0x37, 0x35, 0x34, 0x32, 0x30, 0x2f, 0x2d, 0x2c
	};
	uint8_t laibao_data0[1] = {0x08};
	uint8_t laibao_data1[37] = {0x80, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
		0x34, 0x32, 0x31, 0x2f, 0x2e, 0x2c, 0x2b, 0x2a, 0x0, 0x0, 0x0, 0x0, 0x1, 0x4, 0x6, 0x9,
		0x0, 0xd0, 0x07, 0x0, 0x3c, 0x0, 0x64, 0x0, 0xcd, 0xc8, 0xcd, 0xd0, 0x07
	};
	uint8_t laibao_data2[3] = {0x5, 0x2, 0x3};
	uint8_t laibao_data3[3] = {0x40, 0x10, 0x20};
	uint8_t laibao_data4[3] = {0x68, 0x43, 0x5c};
	uint8_t laibao_data5[2] = {0x90, 0x1};
	uint8_t laibao_data6[2] = {0x12, 0x13};

	pr_info("sensor:0x%x", ts->config_id.sensor);
	if (ts->config_id.sensor == 0x31) {
		pr_info("notice:change the TPK fw config!\n");
		i2c_smbus_write_byte_data(ts->i2c_client, 0xff, 1);
		synaptics_rmi4_i2c_write(ts, 0x11e, tpk_data, 16);
		ret = i2c_smbus_read_byte_data(ts->i2c_client, 0x72);
		i2c_smbus_write_byte_data(ts->i2c_client, 0x72, ret|0x04);
		i2c_smbus_write_byte_data(ts->i2c_client, 0xff, 0);
	}
	if (ts->config_id.sensor == 0x37) {
		pr_info("notice:change the LAIBAO fw config!\n");
		i2c_smbus_write_byte_data(ts->i2c_client, 0xff, 1);
		synaptics_rmi4_i2c_write(ts, 0x119, laibao_data0, 1);
		synaptics_rmi4_i2c_write(ts, 0x11e, laibao_data1, 37);
		synaptics_rmi4_i2c_write(ts, 0x14b, laibao_data2, 3);
		synaptics_rmi4_i2c_write(ts, 0x153, laibao_data3, 3);
		synaptics_rmi4_i2c_write(ts, 0x15b, laibao_data4, 3);
		synaptics_rmi4_i2c_write(ts, 0x15f, laibao_data5, 2);
		synaptics_rmi4_i2c_write(ts, 0x16b, laibao_data6, 2);
		ret = i2c_smbus_read_byte_data(ts->i2c_client, 0x72);
		i2c_smbus_write_byte_data(ts->i2c_client, 0x72, ret|0x04);
		i2c_smbus_write_byte_data(ts->i2c_client, 0xff, 0);
	}

#endif

}


 /**
 * synaptics_rmi4_probe()
 *
 * Called by the kernel when an association with an I2C device of the
 * same name is made (after doing i2c_add_driver).
 *
 * This function allocates and initializes the resources for the driver
 * as an input driver, turns on the power to the sensor, queries the
 * sensor for its supported Functions and characteristics, registers
 * the driver to the input subsystem, sets up the interrupt, handles
 * the registration of the early_suspend and late_resume functions,
 * and creates a work queue for detection of other expansion Function
 * modules.
 */
static int synaptics_rmi4_pinctrl_init(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;

	/* Get pinctrl if target uses pinctrl */
	rmi4_data->ts_pinctrl = devm_pinctrl_get(&(rmi4_data->i2c_client->dev));
	if (IS_ERR_OR_NULL(rmi4_data->ts_pinctrl)) {
		dev_dbg(&rmi4_data->i2c_client->dev,
			"Target does not use pinctrl\n");
		retval = PTR_ERR(rmi4_data->ts_pinctrl);
		rmi4_data->ts_pinctrl = NULL;
		return retval;
	}

	rmi4_data->gpio_state_active
		= pinctrl_lookup_state(rmi4_data->ts_pinctrl, "pmx_ts_active");
	if (IS_ERR_OR_NULL(rmi4_data->gpio_state_active)) {
		dev_dbg(&rmi4_data->i2c_client->dev,
			"Can not get ts default pinstate\n");
		retval = PTR_ERR(rmi4_data->gpio_state_active);
		rmi4_data->ts_pinctrl = NULL;
		return retval;
	}

	rmi4_data->gpio_state_suspend
		= pinctrl_lookup_state(rmi4_data->ts_pinctrl, "pmx_ts_suspend");
	if (IS_ERR_OR_NULL(rmi4_data->gpio_state_suspend)) {
		dev_dbg(&rmi4_data->i2c_client->dev,
			"Can not get ts sleep pinstate\n");
		retval = PTR_ERR(rmi4_data->gpio_state_suspend);
		rmi4_data->ts_pinctrl = NULL;
		return retval;
	}

	return 0;
}

static int synpatics_rmi4_pinctrl_select(struct synaptics_rmi4_data *rmi4_data,
						bool on)
{
	struct pinctrl_state *pins_state;
	int ret;

	pins_state = on ? rmi4_data->gpio_state_active
		: rmi4_data->gpio_state_suspend;
	if (!IS_ERR_OR_NULL(pins_state)) {
		ret = pinctrl_select_state(rmi4_data->ts_pinctrl, pins_state);
		if (ret) {
			dev_err(&rmi4_data->i2c_client->dev,
				"can not set %s pins\n",
				on ? "pmx_ts_active" : "pmx_ts_suspend");
			return ret;
		}
	} else
		dev_err(&rmi4_data->i2c_client->dev,
			"not a valid '%s' pinstate\n",
				on ? "pmx_ts_active" : "pmx_ts_suspend");

	return 0;
}
static int  synaptics_rmi4_probe(struct i2c_client *client,
		const struct i2c_device_id *dev_id)
{
	int retval;
	unsigned char ii;
	unsigned char attr_count;
	struct proc_dir_entry *dir, *refresh;
	struct synaptics_rmi4_f1a_handle *f1a;
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_data *rmi4_data;
	struct synaptics_rmi4_device_info *rmi;
	struct synaptics_dsx_platform_data *platform_data;
	char chiptype[16], sensor[16];
	int fw_ver = 0;

	pr_info("%s:start to probe\n", __func__);
	if (!i2c_check_functionality(client->adapter,
			I2C_FUNC_SMBUS_BYTE_DATA)) {
		dev_err(&client->dev,
				"%s: SMBus byte data not supported\n",
				__func__);
		return -EIO;
	}

	platform_data = kzalloc(sizeof(struct synaptics_dsx_platform_data), GFP_KERNEL);
	if (!platform_data)
		return -EINVAL;

	platform_data->client = client;
	retval = syna_parse_dt(&client->dev, platform_data);
	if (retval < 0)
		goto err_devm;

	rmi4_data = kzalloc(sizeof(*rmi4_data) * 2, GFP_KERNEL);
	if (!rmi4_data) {
		retval = -ENOMEM;
		goto err_devm;

	}

	rmi = &(rmi4_data->rmi4_mod_info);

	rmi4_data->input_dev = input_allocate_device();
	if (rmi4_data->input_dev == NULL) {
		retval = -ENOMEM;
		goto err_input_device;
	}

	retval = touchscreen_gpio_init(&client->dev, 1, platform_data->vdd, platform_data->vbus,
	platform_data->reset_gpio, platform_data->irq_gpio);
	if (retval < 0) {
		pr_err("%s, gpio init failed! %d\n", __func__, retval);
		goto err_regulator;
	}

	rmi4_data->i2c_client = client;
	rmi4_data->current_page = MASK_8BIT;
	rmi4_data->board = platform_data;
	rmi4_data->touch_stopped = false;
	rmi4_data->sensor_sleep = false;

	rmi4_data->i2c_read = synaptics_rmi4_i2c_read;
	rmi4_data->i2c_write = synaptics_rmi4_i2c_write;
	rmi4_data->irq_enable = synaptics_rmi4_irq_acquire;
	rmi4_data->reset_device = synaptics_rmi4_reset_device;

	rmi4_data->flip_x = rmi4_data->board->x_flip;
	rmi4_data->flip_y = rmi4_data->board->y_flip;
	rmi4_data->swap_axes = false;

	rmi4_data->reset_delay_ms = rmi4_data->board->reset_delay_ms ?
		rmi4_data->board->reset_delay_ms : 90;

	init_waitqueue_head(&rmi4_data->wait);
	mutex_init(&(rmi4_data->rmi4_io_ctrl_mutex));

	touchscreen_reset(0, platform_data->reset_gpio);
	msleep(100);
	touchscreen_power(1);
	usleep_range(10000, 10500);
	touchscreen_reset(1, platform_data->reset_gpio);
	msleep(rmi4_data->reset_delay_ms);

	exp_data.queue_work = false;

	if (!detect_device(rmi4_data)) {
		pr_info("%s, device is not exsit.\n", __func__);
		retval = -EIO;
		goto err_detect;
	}

	retval = synaptics_rmi4_pinctrl_init(rmi4_data);
	if (!retval && rmi4_data->ts_pinctrl) {
		retval = synpatics_rmi4_pinctrl_select(rmi4_data, true);
		if (retval < 0)
			goto err_query_device;
	}

	retval = synaptics_rmi4_query_device(rmi4_data);
	if (retval < 0) {
		dev_err(&client->dev,
				"%s: Failed to query device\n",
				__func__);
		goto err_pinctrl;
	}

	if (rmi4_data->swap_axes)
		synaptics_rmi4_swap_axis(rmi4_data);

	i2c_set_clientdata(client, rmi4_data);
	synaptics_wq = create_singlethread_workqueue("synaptics_wq");
	if (!synaptics_wq) {
		pr_err("Could not create work queue synaptics_wq: no memory");
		retval = -ESRCH;
		goto err_create_singlethread;
	}
	INIT_WORK(&rmi4_data->work, synaptics_work_func);

	syna_rmi4_resume_wq = create_singlethread_workqueue("syna_rmi4_resume_wq");
	if (!syna_rmi4_resume_wq) {
		pr_err("Could not create work queue syna_rmi4_resume_wq: no memory");
		retval = -ESRCH;
		goto err_create_singlethread;
	}
	INIT_WORK(&syna_rmi4_resume_work, synaptics_rmi4_resume_pm);

	syn_ts = rmi4_data;
	synaptics_get_configid(syn_ts, (char *)&chiptype, (char *)&sensor, &fw_ver);

	zte_synaptics_change_fw_config(syn_ts);

	rmi4_data->input_dev->name = DRIVER_NAME;
	rmi4_data->input_dev->phys = INPUT_PHYS_NAME;
	rmi4_data->input_dev->id.bustype = BUS_I2C;
	rmi4_data->input_dev->id.product = SYNAPTICS_DSX_DRIVER_PRODUCT;
	rmi4_data->input_dev->id.version = SYNAPTICS_DSX_DRIVER_VERSION;
	rmi4_data->input_dev->dev.parent = &client->dev;
	input_set_drvdata(rmi4_data->input_dev, rmi4_data);

	set_bit(EV_SYN, rmi4_data->input_dev->evbit);
	set_bit(EV_KEY, rmi4_data->input_dev->evbit);
	set_bit(EV_ABS, rmi4_data->input_dev->evbit);
	set_bit(BTN_TOUCH, rmi4_data->input_dev->keybit);
	set_bit(BTN_TOOL_FINGER, rmi4_data->input_dev->keybit);

#ifdef INPUT_PROP_DIRECT
	set_bit(INPUT_PROP_DIRECT, rmi4_data->input_dev->propbit);
#endif

	rmi4_data->sensor_max_y = rmi4_data->sensor_max_y - rmi4_data->board->maxy_offset;

	input_set_abs_params(rmi4_data->input_dev, ABS_X,
				 0, rmi4_data->sensor_max_x, 0, 0);
	input_set_abs_params(rmi4_data->input_dev, ABS_Y,
				 0, rmi4_data->sensor_max_y, 0, 0);
	input_set_abs_params(rmi4_data->input_dev, ABS_PRESSURE,
				 0, 255, 0, 0);
	input_set_abs_params(rmi4_data->input_dev,
			ABS_MT_POSITION_X, 0,
			rmi4_data->sensor_max_x, 0, 0);
	input_set_abs_params(rmi4_data->input_dev,
			ABS_MT_POSITION_Y, 0,
			rmi4_data->sensor_max_y, 0, 0);
	input_set_abs_params(rmi4_data->input_dev,
			ABS_MT_PRESSURE, 0, 255, 0, 0);
#ifdef REPORT_2D_W
	input_set_abs_params(rmi4_data->input_dev,
			ABS_MT_TOUCH_MAJOR, 0,
			MAX_ABS_MT_TOUCH_MAJOR, 0, 0);
#endif

#ifdef TYPE_B_PROTOCOL
#ifdef KERNEL_ABOVE_3_7
	/* input_mt_init_slots now has a "flags" parameter */
	input_mt_init_slots(rmi4_data->input_dev,
			rmi4_data->num_of_fingers, INPUT_MT_DIRECT);
#else
	input_mt_init_slots(rmi4_data->input_dev,
			rmi4_data->num_of_fingers);
#endif
#endif

	f1a = NULL;
	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
			if (fhandler->fn_number == SYNAPTICS_RMI4_F1A)
				f1a = fhandler->data;
		}
	}

	if (f1a) {
		for (ii = 0; ii < f1a->valid_button_count; ii++) {
			set_bit(f1a->button_map[ii],
					rmi4_data->input_dev->keybit);
			input_set_capability(rmi4_data->input_dev,
					EV_KEY, f1a->button_map[ii]);
		}
	}

	retval = input_register_device(rmi4_data->input_dev);
	if (retval) {
		dev_err(&client->dev,
				"%s: Failed to register input device\n",
				__func__);
		goto err_register_input;
	}


#ifdef CONFIG_HAS_EARLYSUSPEND
	rmi4_data->early_suspend.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN + 1;
	rmi4_data->early_suspend.suspend = synaptics_rmi4_early_suspend;
	rmi4_data->early_suspend.resume = synaptics_rmi4_late_resume;
	register_early_suspend(&rmi4_data->early_suspend);
#endif

	if (!exp_data.initialized) {
		mutex_init(&exp_data.mutex);
		INIT_LIST_HEAD(&exp_data.list);
		exp_data.initialized = 1;
	}

	exp_data.workqueue =
			create_singlethread_workqueue("dsx_exp_workqueue");
	INIT_DELAYED_WORK(&exp_data.work,
			synaptics_rmi4_detection_work);
	exp_data.rmi4_data = rmi4_data;
	exp_data.queue_work = true;
	queue_delayed_work(exp_data.workqueue,
			&exp_data.work,
			msecs_to_jiffies(EXP_FN_WORK_DELAY_MS));

	if (platform_data->gpio_config) {
		retval = platform_data->gpio_config(platform_data->irq_gpio,
							true);
		if (retval < 0) {
			dev_err(&client->dev,
					"%s: Failed to configure GPIO\n",
					__func__);
			goto err_gpio;
		}
	}


	rmi4_data->irq = gpio_to_irq(platform_data->irq_gpio);

	retval = synaptics_rmi4_irq_acquire(rmi4_data, true);
	if (retval < 0) {
		dev_err(&client->dev,
				"%s: Failed to acquire irq\n",
				__func__);

		goto err_enable_irq;
	}


	for (attr_count = 0; attr_count < ARRAY_SIZE(attrs); attr_count++) {
		retval = sysfs_create_file(&rmi4_data->input_dev->dev.kobj,
				&attrs[attr_count].attr);
		if (retval < 0) {
			dev_err(&client->dev,
					"%s: Failed to create sysfs attributes\n",
					__func__);
			goto err_sysfs;
		}
	}

	#if defined(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_V10)
	rmi4_fw_update_module_init();
	syna_fwupdate_init(client);
	#endif
	#if defined(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_TEST_REPORTING_V10)
	rmi4_f54_module_init();
	#endif
	#if defined(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_RMI_DEV_V10)
	rmidev_module_init();
	#endif

	#ifdef ZTE_FASTMMI_MANUFACTURING_VERSION
	syn_ts->fb_ready = true;
	syn_ts->stay_awake = true;
	pr_info("%s: fb_ready = %d, stay_awake = %d\n",
		__func__,
		syn_ts->fb_ready,
		syn_ts->stay_awake);
	#endif

	rmi4_data->fb_notif.notifier_call = fb_notifier_callback;
	retval = fb_register_client(&rmi4_data->fb_notif);
	if (retval)
		dev_err(&rmi4_data->i2c_client->dev,
			"Unable to register fb_notifier: %d\n",
			retval);

	dir = proc_mkdir("touchscreen", NULL);
	refresh = proc_create("ts_information", 0664, dir, &proc_ops);
	if (refresh == NULL)
		pr_info("proc_create ts_information failed!\n");

	refresh = proc_create("ts_update", 0444, dir, &update_proc_ops);
	if (refresh == NULL)
		pr_info("proc_create ts_update failed!\n");

	refresh = proc_create("ts_rawdata_read", 0664, dir, &rawdata_read_proc_ops);
	if (refresh == NULL)
		pr_info("proc_create ts_rawdata_read failed!\n");

	refresh = proc_create("ts_rawdata_test", 0664, dir, &rawdata_test_proc_ops);
	if (refresh == NULL)
		pr_info("proc_create ts_rawdata_test failed!\n");

	refresh = proc_create("ts_short_circuit_test", 0664, dir, &short_circuit_test_proc_ops);
	if (refresh == NULL)
		pr_info("proc_create ts_short_circuit_test failed!\n");

	pr_info("%s: probe end\n", __func__);
	return retval;

err_sysfs:
	for (attr_count--; attr_count >= 0; attr_count--) {
		sysfs_remove_file(&rmi4_data->input_dev->dev.kobj,
				&attrs[attr_count].attr);
	}

err_enable_irq:
err_gpio:
	input_unregister_device(rmi4_data->input_dev);

err_register_input:
err_create_singlethread:
err_query_device:

	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
			if (fhandler->fn_number == SYNAPTICS_RMI4_F1A)
				synaptics_rmi4_f1a_kfree(fhandler);
			else
				kfree(fhandler->data);

			kfree(fhandler);
		}
	}

err_detect:
	touchscreen_power(0);
	touchscreen_gpio_init(&client->dev, 0, platform_data->vdd, platform_data->vbus,
		platform_data->reset_gpio, platform_data->irq_gpio);
err_pinctrl:
	if (rmi4_data->ts_pinctrl) {
		retval = synpatics_rmi4_pinctrl_select(rmi4_data, false);
		if (retval < 0)
			pr_err("Cannot get idle pinctrl state\n");
	}


err_regulator:
	input_free_device(rmi4_data->input_dev);
	rmi4_data->input_dev = NULL;

err_input_device:
	kfree(rmi4_data);
err_devm:
	kfree(platform_data);
	pr_info("%s:end due to error\n", __func__);
	return retval;
}

 /**
 * synaptics_rmi4_remove()
 *
 * Called by the kernel when the association with an I2C device of the
 * same name is broken (when the driver is unloaded).
 *
 * This function terminates the work queue, stops sensor data acquisition,
 * frees the interrupt, unregisters the driver from the input subsystem,
 * turns off the power to the sensor, and frees other allocated resources.
 */
static int  synaptics_rmi4_remove(struct i2c_client *client)
{
	unsigned char attr_count;
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_data *rmi4_data = i2c_get_clientdata(client);
	struct synaptics_rmi4_device_info *rmi;
	const struct synaptics_dsx_platform_data *platform_data =
			rmi4_data->board;
#if defined(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_V10)
		syna_fwupdate_deinit(client);
#endif

	rmi = &(rmi4_data->rmi4_mod_info);

	cancel_delayed_work_sync(&exp_data.work);
	flush_workqueue(exp_data.workqueue);
	destroy_workqueue(exp_data.workqueue);

	rmi4_data->touch_stopped = true;
	wake_up(&rmi4_data->wait);

	synaptics_rmi4_irq_acquire(rmi4_data, false);

	for (attr_count = 0; attr_count < ARRAY_SIZE(attrs); attr_count++) {
		sysfs_remove_file(&rmi4_data->input_dev->dev.kobj,
				&attrs[attr_count].attr);
	}

	input_unregister_device(rmi4_data->input_dev);

	touchscreen_power(0);
	touchscreen_gpio_init(&client->dev, 0, platform_data->vdd, platform_data->vbus,
		platform_data->reset_gpio, platform_data->irq_gpio);


	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
			if (fhandler->fn_number == SYNAPTICS_RMI4_F1A)
				synaptics_rmi4_f1a_kfree(fhandler);
			else
				kfree(fhandler->data);
			kfree(fhandler);
		}
	}
	input_free_device(rmi4_data->input_dev);

	kfree(rmi4_data);

	return 0;
}

#ifdef CONFIG_PM
 /**
 * synaptics_rmi4_sensor_sleep()
 *
 * Called by synaptics_rmi4_early_suspend() and synaptics_rmi4_suspend().
 *
 * This function stops finger data acquisition and puts the sensor to sleep.
 */
static void synaptics_rmi4_sensor_sleep(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned char device_ctrl;

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			rmi4_data->f01_ctrl_base_addr,
			&device_ctrl,
			sizeof(device_ctrl));
	if (retval < 0) {
		dev_err(&(rmi4_data->input_dev->dev),
				"%s: Failed to enter sleep mode\n",
				__func__);
		rmi4_data->sensor_sleep = false;
		return;
	}

	device_ctrl = (device_ctrl & ~MASK_3BIT);
	device_ctrl = (device_ctrl | NO_SLEEP_OFF | SENSOR_SLEEP);

	retval = synaptics_rmi4_i2c_write(rmi4_data,
			rmi4_data->f01_ctrl_base_addr,
			&device_ctrl,
			sizeof(device_ctrl));
	if (retval < 0) {
		dev_err(&(rmi4_data->input_dev->dev),
				"%s: Failed to enter sleep mode\n",
				__func__);
		rmi4_data->sensor_sleep = false;
		return;
	}
	rmi4_data->sensor_sleep = true;
}

 /**
 * synaptics_rmi4_sensor_wake()
 *
 * Called by synaptics_rmi4_resume() and synaptics_rmi4_late_resume().
 *
 * This function wakes the sensor from sleep.
 */
static void synaptics_rmi4_sensor_wake(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned char device_ctrl;

	retval = synaptics_rmi4_i2c_read(rmi4_data,
			rmi4_data->f01_ctrl_base_addr,
			&device_ctrl,
			sizeof(device_ctrl));
	if (retval < 0) {
		dev_err(&(rmi4_data->input_dev->dev),
				"%s: Failed to wake from sleep mode\n",
				__func__);
		rmi4_data->sensor_sleep = true;
		return;
	}

	device_ctrl = (device_ctrl & ~MASK_3BIT);
	device_ctrl = (device_ctrl | NO_SLEEP_OFF | NORMAL_OPERATION);

	retval = synaptics_rmi4_i2c_write(rmi4_data,
			rmi4_data->f01_ctrl_base_addr,
			&device_ctrl,
			sizeof(device_ctrl));
	if (retval < 0) {
		dev_err(&(rmi4_data->input_dev->dev),
				"%s: Failed to wake from sleep mode\n",
				__func__);
		rmi4_data->sensor_sleep = true;
		return;
	}
	rmi4_data->sensor_sleep = false;
}

#ifdef CONFIG_HAS_EARLYSUSPEND
 /**
 * synaptics_rmi4_early_suspend()
 *
 * Called by the kernel during the early suspend phase when the system
 * enters suspend.
 *
 * This function calls synaptics_rmi4_sensor_sleep() to stop finger
 * data acquisition and put the sensor to sleep.
 */
static void synaptics_rmi4_early_suspend(struct early_suspend *h)
{
	struct synaptics_rmi4_data *rmi4_data =
			container_of(h, struct synaptics_rmi4_data,
			early_suspend);
	rmi4_data->touch_stopped = true;
	wake_up(&rmi4_data->wait);
	synaptics_rmi4_irq_enable(rmi4_data, false);
	synaptics_rmi4_sensor_sleep(rmi4_data);

	if (rmi4_data->full_pm_cycle)
		synaptics_rmi4_suspend(&(rmi4_data->input_dev->dev));
}

 /**
 * synaptics_rmi4_late_resume()
 *
 * Called by the kernel during the late resume phase when the system
 * wakes up from suspend.
 *
 * This function goes through the sensor wake process if the system wakes
 * up from early suspend (without going into suspend).
 */
static void synaptics_rmi4_late_resume(struct early_suspend *h)
{
	struct synaptics_rmi4_data *rmi4_data =
			container_of(h, struct synaptics_rmi4_data,
			early_suspend);

	if (rmi4_data->full_pm_cycle)
		synaptics_rmi4_resume(&(rmi4_data->input_dev->dev));

	if (rmi4_data->sensor_sleep == true) {
		synaptics_rmi4_sensor_wake(rmi4_data);
		rmi4_data->touch_stopped = false;
		synaptics_rmi4_irq_enable(rmi4_data, true);
	}
}
#endif

static int fb_notifier_callback(struct notifier_block *self,
	unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	int *blank;
	struct synaptics_rmi4_data *ts =
		container_of(self, struct synaptics_rmi4_data, fb_notif);

	if (evdata && evdata->data && event == FB_EVENT_BLANK &&
			ts && ts->i2c_client) {
		blank = evdata->data;
		if (*blank == FB_BLANK_UNBLANK) {
			queue_work(syna_rmi4_resume_wq, &syna_rmi4_resume_work);
			pr_info("%s: ts->fb_ready = %d\n", __func__, ts->fb_ready);
			ts->fb_ready = true;
		} else if ((*blank == FB_BLANK_POWERDOWN) || (*blank == FB_BLANK_NORMAL)) {
			synaptics_rmi4_suspend_pm();
			pr_info("%s: ts->fb_ready = %d\n", __func__, ts->fb_ready);
			ts->fb_ready = false;
		}
	}

	return 0;
}

int synaptics_rmi4_suspend_pm(void)
{
	pr_info("%s:start\n", __func__);

#ifdef ZTE_FASTMMI_MANUFACTURING_VERSION
	if (syn_ts->stay_awake) {
		pr_info("%s:can not suspend and return\n", __func__);
		return 0;
	}
#endif
	if (!syn_ts->sensor_sleep) {
		syn_ts->touch_stopped = true;
		wake_up(&syn_ts->wait);
		synaptics_rmi4_irq_enable(syn_ts, false);
		synaptics_rmi4_sensor_sleep(syn_ts);
	}

	pr_info("%s:end\n", __func__);

	return 0;
}

void synaptics_rmi4_resume_pm(struct work_struct *work)
{
	pr_info("%s: start\n", __func__);

	if (syn_ts->sensor_sleep) {
		synaptics_rmi4_sensor_wake(syn_ts);
		zte_synaptics_change_fw_config(syn_ts);
		syn_ts->touch_stopped = false;
		synaptics_rmi4_irq_enable(syn_ts, true);
	}

	timespec = current_kernel_time();
	rtc_time_to_tm(timespec.tv_sec, &time);

	pr_info("%s: resume device\n", __func__);
}


static const struct dev_pm_ops synaptics_rmi4_dev_pm_ops = {
	/*.suspend = synaptics_rmi4_suspend, */
	/*.resume = synaptics_rmi4_resume, */
};
#endif

static const struct i2c_device_id synaptics_rmi4_id_table[] = {
	{DRIVER_NAME, 0},
	{},
};
MODULE_DEVICE_TABLE(i2c, synaptics_rmi4_id_table);
#ifdef CONFIG_OF
static const struct of_device_id syna_match_table[] = {
	{ .compatible = "synaptics,syna-ts",},
	{ },
};
#endif


static struct i2c_driver synaptics_rmi4_driver = {
	.driver = {
		.name = "syna-touchscreen",
		.owner = THIS_MODULE,
#ifdef CONFIG_PM
		.pm = &synaptics_rmi4_dev_pm_ops,
#endif
#ifdef CONFIG_OF
		.of_match_table = syna_match_table,
#endif

	},
	.probe = synaptics_rmi4_probe,
	.remove = synaptics_rmi4_remove,
	.id_table = synaptics_rmi4_id_table,

};

 /**
 * synaptics_rmi4_init()
 *
 * Called by the kernel during do_initcalls (if built-in)
 * or when the driver is loaded (if a module).
 *
 * This function registers the driver to the I2C subsystem.
 *
 */
static int __init synaptics_rmi4_init(void)
{
	pr_info("hjy synaptics_rmi4_init\n");
	return i2c_add_driver(&synaptics_rmi4_driver);
}

 /**
 * synaptics_rmi4_exit()
 *
 * Called by the kernel when the driver is unloaded.
 *
 * This function unregisters the driver from the I2C subsystem.
 *
 */
static void __exit synaptics_rmi4_exit(void)
{
	i2c_del_driver(&synaptics_rmi4_driver);
}

module_init(synaptics_rmi4_init);
module_exit(synaptics_rmi4_exit);

MODULE_AUTHOR("Synaptics, Inc.");
MODULE_DESCRIPTION("Synaptics DSX I2C Touch Driver");
MODULE_LICENSE("GPL v2");
