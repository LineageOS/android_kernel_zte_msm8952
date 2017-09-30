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

#ifndef _SYNAPTICS_DSX_TEST_REPORTING_
#define _SYNAPTICS_DSX_TEST_REPORTING_

#include <linux/input/synaptics_dsx_v1_0.h>
#include "synaptics_dsx_i2c.h"

struct f54_query {
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

			/* query 7 */
			unsigned char curve_compensation_mode:2;
			unsigned char f54_query7_b2__7:6;

			/* query 8 */
			unsigned char f54_query8_b0:1;
			unsigned char has_iir_filter:1;
			unsigned char has_cmn_removal:1;
			unsigned char has_cmn_maximum:1;
			unsigned char has_touch_hysteresis:1;
			unsigned char has_edge_compensation:1;
			unsigned char has_per_frequency_noise_control:1;
			unsigned char has_enhanced_stretch:1;

			/* query 9 */
			unsigned char has_force_fast_relaxation:1;
			unsigned char has_multi_metric_state_machine:1;
			unsigned char has_signal_clarity:1;
			unsigned char has_variance_metric:1;
			unsigned char has_0d_relaxation_control:1;
			unsigned char has_0d_acquisition_control:1;
			unsigned char has_status:1;
			unsigned char has_slew_metric:1;

			/* query 10 */
			unsigned char has_h_blank:1;
			unsigned char has_v_blank:1;
			unsigned char has_long_h_blank:1;
			unsigned char has_startup_fast_relaxation:1;
			unsigned char has_esd_control:1;
			unsigned char has_noise_mitigation2:1;
			unsigned char has_noise_state:1;
			unsigned char has_energy_ratio_relaxation:1;

			/* query 11 */
			unsigned char has_excessive_noise_reporting:1;
			unsigned char has_slew_option:1;
			unsigned char has_two_overhead_bursts:1;
			unsigned char has_query13:1;
			unsigned char has_one_overhead_burst:1;
			unsigned char f54_query11_b5:1;
			unsigned char has_ctrl88:1;
			unsigned char has_query15:1;

			/* query 12 */
			unsigned char number_of_sensing_frequencies:4;
			unsigned char f54_query12_b4__7:4;

			/* query 13 */
			unsigned char has_ctrl86:1;
			unsigned char has_ctrl87:1;
			unsigned char has_ctrl87_sub0:1;
			unsigned char has_ctrl87_sub1:1;
			unsigned char has_ctrl87_sub2:1;
			unsigned char has_cidim:1;
			unsigned char has_noise_mitigation_enhancement:1;
			unsigned char has_rail_im:1;
		} __packed;
		unsigned char data[15];
	};
};

enum f54_report_types {
	F54_8BIT_IMAGE = 1,
	F54_16BIT_IMAGE = 2,
	F54_RAW_16BIT_IMAGE = 3,
	F54_HIGH_RESISTANCE = 4,
	F54_TX_TO_TX_SHORT = 5,
	F54_RX_TO_RX1 = 7,
	F54_TRUE_BASELINE = 9,
	F54_FULL_RAW_CAP_MIN_MAX = 13,
	F54_RX_OPENS1 = 14,
	F54_TX_OPEN = 15,
	F54_TX_TO_GROUND = 16,
	F54_RX_TO_RX2 = 17,
	F54_RX_OPENS2 = 18,
	F54_FULL_RAW_CAP = 19,
	F54_FULL_RAW_CAP_RX_COUPLING_COMP = 20,
	F54_SENSOR_SPEED = 22,
	F54_ADC_RANGE = 23,
	F54_TREX_OPENS = 24,
	F54_TREX_TO_GND = 25,
	F54_TREX_SHORTS = 26,
	INVALID_REPORT_TYPE = -1,
};

struct f54_control {
	struct f54_control_0 *reg_0;
	struct f54_control_1 *reg_1;
	struct f54_control_2 *reg_2;
	struct f54_control_3 *reg_3;
	struct f54_control_4__6 *reg_4__6;
	struct f54_control_7 *reg_7;
	struct f54_control_8__9 *reg_8__9;
	struct f54_control_10 *reg_10;
	struct f54_control_11 *reg_11;
	struct f54_control_12__13 *reg_12__13;
	struct f54_control_14 *reg_14;
	struct f54_control_15 *reg_15;
	struct f54_control_16 *reg_16;
	struct f54_control_17 *reg_17;
	struct f54_control_18 *reg_18;
	struct f54_control_19 *reg_19;
	struct f54_control_20 *reg_20;
	struct f54_control_21 *reg_21;
	struct f54_control_22__26 *reg_22__26;
	struct f54_control_27 *reg_27;
	struct f54_control_28 *reg_28;
	struct f54_control_29 *reg_29;
	struct f54_control_30 *reg_30;
	struct f54_control_31 *reg_31;
	struct f54_control_32__35 *reg_32__35;
	struct f54_control_36 *reg_36;
	struct f54_control_37 *reg_37;
	struct f54_control_38 *reg_38;
	struct f54_control_39 *reg_39;
	struct f54_control_40 *reg_40;
	struct f54_control_41 *reg_41;
	struct f54_control_57 *reg_57;
	struct f54_control_88 *reg_88;
};

struct f55_query {
	union {
		struct {
			/* query 0 */
			unsigned char num_of_rx_electrodes;

			/* query 1 */
			unsigned char num_of_tx_electrodes;

			/* query 2 */
			unsigned char has_sensor_assignment:1;
			unsigned char has_edge_compensation:1;
			unsigned char curve_compensation_mode:2;
			unsigned char has_ctrl6:1;
			unsigned char has_alternate_transmitter_assignment:1;
			unsigned char has_single_layer_multi_touch:1;
			unsigned char has_query5:1;
		} __packed;
		unsigned char data[3];
	};
};

struct synaptics_rmi4_fn55_desc {
	unsigned short query_base_addr;
	unsigned short control_base_addr;
};

struct synaptics_rmi4_f54_handle {
	bool no_auto_cal;
	unsigned char status;
	unsigned char intr_mask;
	unsigned char intr_reg_num;
	unsigned char rx_assigned;
	unsigned char tx_assigned;
	unsigned char *report_data;
	unsigned short query_base_addr;
	unsigned short control_base_addr;
	unsigned short data_base_addr;
	unsigned short command_base_addr;
	unsigned short fifoindex;
	unsigned int report_size;
	unsigned int data_buffer_size;
	enum f54_report_types report_type;
	struct mutex status_mutex;
	struct mutex data_mutex;
	struct mutex control_mutex;
	struct f54_query query;
	struct f54_control control;
	struct kobject *attr_dir;
	struct hrtimer watchdog;
	struct work_struct timeout_work;
	struct delayed_work status_work;
	struct workqueue_struct *status_workqueue;
	struct synaptics_rmi4_access_ptr *fn_ptr;
	struct synaptics_rmi4_data *rmi4_data;
	struct synaptics_rmi4_fn55_desc *fn55;
};
#endif
