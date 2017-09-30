/* Copyright (c) 2011-2014, The Linux Foundation. All rights reserved.
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

#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/delay.h>
#include <linux/crc32.h>
#include "msm_sd.h"
#include "msm_cci.h"
#include "zte_eeprom.h"

#undef CDBG
#ifdef CONFIG_MSMB_CAMERA_DEBUG
#define CDBG(fmt, args...) pr_err(fmt, ##args)
#else
#define CDBG(fmt, args...) do { } while (0)
#endif

#define ZTE_EEPROM_ERROR	-1

enum {
	Invlid_Group,
	Group_One,
	Group_Two,
	Group_Three,
	Group_Four,
} Group_t;

typedef struct {
	uint16_t id;
	const char *sensor_module_name;
	const char *chromtix_lib_name;
	const char *default_chromtix_lib_name;
} MODULE_Map_Table;

#define IMX214_SENSOR_INFO_MODULE_ID_SUNNY		0x01
#define IMX214_SENSOR_INFO_MODULE_ID_TRULY		0x02
#define IMX214_SENSOR_INFO_MODULE_ID_A_KERR		0x03
#define IMX214_SENSOR_INFO_MODULE_ID_LITEARRAY	0x04
#define IMX214_SENSOR_INFO_MODULE_ID_DARLING		0x05
#define IMX214_SENSOR_INFO_MODULE_ID_QTECH		0x06
#define IMX214_SENSOR_INFO_MODULE_ID_QFLIM		0x07
#define IMX214_SENSOR_INFO_MODULE_ID_FOXCONN	0x11
#define IMX214_SENSOR_INFO_MODULE_ID_IMPORTEK	0x12
#define IMX214_SENSOR_INFO_MODULE_ID_ALTEK		0x13
#define IMX214_SENSOR_INFO_MODULE_ID_ABICO_ABILITY	0x14
#define IMX214_SENSOR_INFO_MODULE_ID_LITE_ON		0x15
#define IMX214_SENSOR_INFO_MODULE_ID_CHICONY	0x16
#define IMX214_SENSOR_INFO_MODULE_ID_PRIMAX		0x17
#define IMX214_SENSOR_INFO_MODULE_ID_SHARP		0x21
#define IMX214_SENSOR_INFO_MODULE_ID_LITE_ON_NEW		0x22
#define IMX214_SENSOR_INFO_MODULE_ID_MCNEX	0x31
#define IMX214_SENSOR_INFO_MODULE_ID_MCNEX_2	0x33

MODULE_Map_Table IMX214_MODULE_MAP[] = {
	{ IMX214_SENSOR_INFO_MODULE_ID_SUNNY,	"sunny_imx214", "sunny_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_TRULY, "truly_imx214", "truly_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_A_KERR, "a_kerr_imx214", "a_kerr_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_LITEARRAY, "litearray_imx214", "litearray_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_DARLING, "darling_imx214", "darling_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_QTECH, "qtech_imx214", "qtech_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_QFLIM, "qflim_imx214", "qflim_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_FOXCONN, "foxconn_imx214", "foxconn_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_IMPORTEK, "importek_imx214", "importek_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_ALTEK, "altek_imx214", "altek_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_ABICO_ABILITY, "abico_ability_imx214", "abico_ability_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_LITE_ON, "lite_on_imx214", "lite_on_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_CHICONY, "chicony_imx214", "chicony_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_PRIMAX, "primax_imx214", "primax_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_SHARP, "sharp_imx214", "sharp_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_LITE_ON_NEW, "lite_on_new_imx214", "lite_on_new_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_MCNEX, "mcnex_imx214", "mcnex_imx214", NULL},
	{ IMX214_SENSOR_INFO_MODULE_ID_MCNEX_2, "mcnex_2_imx214", "mcnex_2_imx214", NULL},
};

#define T4KB3_SENSOR_INFO_MODULE_ID_SUNNY		0x01
#define T4KB3_SENSOR_INFO_MODULE_ID_TRULY		0x02
#define T4KB3_SENSOR_INFO_MODULE_ID_A_KERR		0x03
#define T4KB3_SENSOR_INFO_MODULE_ID_LITEARRAY	0x04
#define T4KB3_SENSOR_INFO_MODULE_ID_DARLING		0x05
#define T4KB3_SENSOR_INFO_MODULE_ID_QTECH		0x06
#define T4KB3_SENSOR_INFO_MODULE_ID_QFLIM		0x07
#define T4KB3_SENSOR_INFO_MODULE_ID_RICHTEK		0x08
#define T4KB3_SENSOR_INFO_MODULE_ID_SEASONS	0x10
#define T4KB3_SENSOR_INFO_MODULE_ID_FOXCONN	0x11
#define T4KB3_SENSOR_INFO_MODULE_ID_IMPORTEK	0x12
#define T4KB3_SENSOR_INFO_MODULE_ID_ALTEK		0x13
#define T4KB3_SENSOR_INFO_MODULE_ID_ABICO_ABILITY	0x14
#define T4KB3_SENSOR_INFO_MODULE_ID_LITE_ON		0x15
#define T4KB3_SENSOR_INFO_MODULE_ID_CHICONY	0x16
#define T4KB3_SENSOR_INFO_MODULE_ID_PRIMAX		0x17
#define T4KB3_SENSOR_INFO_MODULE_ID_KINGKOME	0x18
#define T4KB3_SENSOR_INFO_MODULE_ID_GOERTEK	0x19
#define T4KB3_SENSOR_INFO_MODULE_ID_SHARP		0x21
#define T4KB3_SENSOR_INFO_MODULE_ID_MCNEX	0x31
#define T4KB3_SENSOR_INFO_MODULE_ID_SHINETECK		0x32
#define T4KB3_SENSOR_INFO_MODULE_ID_SUNRISE	0x33
#define T4KB3_SENSOR_INFO_MODULE_ID_YUANDA	0x35

MODULE_Map_Table T4KB3_MODULE_MAP[] = {
	{ T4KB3_SENSOR_INFO_MODULE_ID_SUNNY,	"sunny_T4KB3", "sunny_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_TRULY,		"truly_T4KB3", "truly_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_A_KERR,	"a_kerr_T4KB3", "a_kerr_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_LITEARRAY,	"litearray_T4KB3", "litearray_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_DARLING,	"darling_T4KB3", "darling_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_QTECH,		"qtech_T4KB3", "qtech_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_QFLIM,		"qflim_T4KB3", "qflim_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_RICHTEK,	"richtek_T4KB3", "richtek_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_SEASONS,	"seasons_T4KB3", "seasons_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_FOXCONN,	"foxconn_T4KB3", "foxconn_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_IMPORTEK,	"importek_T4KB3", "importek_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_ALTEK,		"altek_T4KB3", "altek_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_ABICO_ABILITY, "abico_ability_T4KB3", "abico_ability_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_LITE_ON,	"lite_on_T4KB3", "lite_on_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_CHICONY,	"chicony_T4KB3", "chicony_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_PRIMAX,	"primax_T4KB3", "primax_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_KINGKOME,	"kingkome_T4KB3", "kingkome_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_GOERTEK,	"goertek_T4KB3", "goertek_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_SHARP,		"sharp_T4KB3", "sharp_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_MCNEX,		"mcnex_T4KB3", "mcnex_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_SHINETECK,	"shineteck_T4KB3", "shineteck_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_SUNRISE,	"sunrise_T4KB3", "sunrise_T4KB3", NULL},
	{ T4KB3_SENSOR_INFO_MODULE_ID_YUANDA,	"yuanda_T4KB3", "yuanda_T4KB3", NULL},
};

#define S5K3M2_SENSOR_INFO_MODULE_ID_SUNNY		0x01
#define S5K3M2_SENSOR_INFO_MODULE_ID_A_KERR		0x03
#define S5K3M2_SENSOR_INFO_MODULE_ID_LITEARRAY	0x04
#define S5K3M2_SENSOR_INFO_MODULE_ID_DARLING		0x05
#define S5K3M2_SENSOR_INFO_MODULE_ID_QTECH		0x06
#define S5K3M2_SENSOR_INFO_MODULE_ID_QFLIM		0x07
#define S5K3M2_SENSOR_INFO_MODULE_ID_TRULY		0x08
#define S5K3M2_SENSOR_INFO_MODULE_ID_FOXCONN	0x11
#define S5K3M2_SENSOR_INFO_MODULE_ID_IMPORTEK	0x12
#define S5K3M2_SENSOR_INFO_MODULE_ID_ALTEK		0x13
#define S5K3M2_SENSOR_INFO_MODULE_ID_ABICO_ABILITY	0x14
#define S5K3M2_SENSOR_INFO_MODULE_ID_LITE_ON		0x15
#define S5K3M2_SENSOR_INFO_MODULE_ID_CHICONY	0x16
#define S5K3M2_SENSOR_INFO_MODULE_ID_PRIMAX		0x17
#define S5K3M2_SENSOR_INFO_MODULE_ID_SHARP		0x21
#define S5K3M2_SENSOR_INFO_MODULE_ID_LITE_ON_NEW		0x22
#define S5K3M2_SENSOR_INFO_MODULE_ID_MCNEX	0x31
#define S5K3M2_SENSOR_INFO_MODULE_ID_MCNEX_2	0xA0

MODULE_Map_Table S5K3M2_MODULE_MAP[] = {
	{ S5K3M2_SENSOR_INFO_MODULE_ID_SUNNY,	"sunny_s5k3m2", "sunny_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_A_KERR,	"a_kerr_s5k3m2", "a_kerr_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_LITEARRAY,	"litearray_s5k3m2", "litearray_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_DARLING,	"darling_s5k3m2", "darling_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_QTECH,		"qtech_s5k3m2", "qtech_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_QFLIM,		"qflim_s5k3m2", "qflim_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_TRULY,		"truly_s5k3m2", "truly_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_FOXCONN,	"foxconn_s5k3m2", "foxconn_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_IMPORTEK,	"importek_s5k3m2", "importek_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_ALTEK,		"altek_s5k3m2", "altek_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_ABICO_ABILITY, "abico_ability_s5k3m2", "abico_ability_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_LITE_ON,	"lite_on_s5k3m2", "lite_on_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_CHICONY,	"chicony_s5k3m2", "chicony_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_PRIMAX,	"primax_s5k3m2", "primax_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_SHARP,		"sharp_s5k3m2", "sharp_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_LITE_ON_NEW,	"lite_on_new_s5k3m2", "lite_on_new_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_MCNEX,		"mcnex_s5k3m2", "mcnex_s5k3m2", NULL},
	{ S5K3M2_SENSOR_INFO_MODULE_ID_MCNEX_2,		"mcnex_2_s5k3m2", "mcnex_2_s5k3m2", NULL},
};

/* add s5k5e8 */
#ifdef CONFIG_BOARD_JASMINE
#define S5K5E8_SENSOR_INFO_MODULE_ID_SUNNY		0x01
#define S5K5E8_SENSOR_INFO_MODULE_ID_QTECH		0x06
#define S5K5E8_SENSOR_INFO_MODULE_ID_A_KERR		0x03
MODULE_Map_Table S5K5E8_MODULE_MAP[] = {
	{ S5K5E8_SENSOR_INFO_MODULE_ID_SUNNY,	"sunny_s5k5e8", "sunny_s5k5e8", NULL},
	{ S5K5E8_SENSOR_INFO_MODULE_ID_QTECH,		"qtech_s5k5e8", "qtech_s5k5e8", NULL},
	{ S5K5E8_SENSOR_INFO_MODULE_ID_A_KERR,		"a_kerr_s5k5e8", "a_kerr_s5k5e8", NULL},
};
#endif
/* end */

/*add imx258*/
#define IMX258_SENSOR_INFO_MODULE_ID_SUNNY		0x01
#define IMX258_SENSOR_INFO_MODULE_ID_A_KERR		0x03
#define IMX258_SENSOR_INFO_MODULE_ID_LITEARRAY	0x04
#define IMX258_SENSOR_INFO_MODULE_ID_DARLING		0x05
#define IMX258_SENSOR_INFO_MODULE_ID_QTECH		0x06
#define IMX258_SENSOR_INFO_MODULE_ID_QFLIM		0x07
#define IMX258_SENSOR_INFO_MODULE_ID_TRULY		0x08
#define IMX258_SENSOR_INFO_MODULE_ID_FOXCONN	0x11
#define IMX258_SENSOR_INFO_MODULE_ID_IMPORTEK	0x12
#define IMX258_SENSOR_INFO_MODULE_ID_ALTEK		0x13
#define IMX258_SENSOR_INFO_MODULE_ID_ABICO_ABILITY	0x14
#define IMX258_SENSOR_INFO_MODULE_ID_LITE_ON		0x15
#define IMX258_SENSOR_INFO_MODULE_ID_CHICONY	0x16
#define IMX258_SENSOR_INFO_MODULE_ID_PRIMAX		0x17
#define IMX258_SENSOR_INFO_MODULE_ID_SHARP		0x21
#define IMX258_SENSOR_INFO_MODULE_ID_LITE_ON_NEW	0x22
#define IMX258_SENSOR_INFO_MODULE_ID_MCNEX	0x31
#define IMX258_SENSOR_INFO_MODULE_ID_MCNEX_2	0xA0

MODULE_Map_Table IMX258_MODULE_MAP[] = {
	{ IMX258_SENSOR_INFO_MODULE_ID_SUNNY,	"sunny_imx258", "sunny_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_A_KERR,	"a_kerr_imx258", "a_kerr_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_LITEARRAY,	"litearray_imx258", "litearray_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_DARLING,	"darling_imx258", "darling_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_QTECH,		"qtech_imx258", "qtech_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_QFLIM,		"qflim_Iimx258", "qflim_IMX258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_TRULY,		"truly_imx258", "truly_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_FOXCONN,	"foxconn_imx258", "foxconn_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_IMPORTEK,	"importek_imx258", "importek_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_ALTEK,		"altek_imx258", "altek_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_ABICO_ABILITY, "abico_ability_imx258", "abico_ability_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_LITE_ON,	"lite_on_imx258", "lite_on_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_CHICONY,	"chicony_imx258", "chicony_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_PRIMAX,	"primax_imx258", "primax_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_SHARP,		"sharp_imx258", "sharp_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_LITE_ON_NEW,	"lite_on_new_imx258", "lite_on_new_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_MCNEX,		"mcnex_imx258", "mcnex_imx258", NULL},
	{ IMX258_SENSOR_INFO_MODULE_ID_MCNEX_2,		"mcnex_2_imx258", "mcnex_2_imx258", NULL},
};

#ifdef CONFIG_BOARD_GEVJON
#define OV5695_SENSOR_INFO_MODULE_ID_SUNNY		0x01
#define OV5695_SENSOR_INFO_MODULE_ID_TRULY		0x02
#define OV5695_SENSOR_INFO_MODULE_ID_A_KERR		0x03
#define OV5695_SENSOR_INFO_MODULE_ID_LITEARRAY	0x04
#define OV5695_SENSOR_INFO_MODULE_ID_DARLING		0x05
#define OV5695_SENSOR_INFO_MODULE_ID_QTECH		0x06

MODULE_Map_Table OV5695_MODULE_MAP[] = {
	{ OV5695_SENSOR_INFO_MODULE_ID_SUNNY,	"sunny_ov5695", "sunny_ov5695", NULL},
	{ OV5695_SENSOR_INFO_MODULE_ID_TRULY,		"truly_ov5695", "truly_ov5695", NULL},
	{ OV5695_SENSOR_INFO_MODULE_ID_A_KERR,	"a_kerr_ov5695", "a_kerr_ov5695", NULL},
	{ OV5695_SENSOR_INFO_MODULE_ID_LITEARRAY,	"litearray_ov5695", "litearray_ov5695", NULL},
	{ OV5695_SENSOR_INFO_MODULE_ID_DARLING,	"darling_ov5695", "darling_tov5695", NULL},
	{ OV5695_SENSOR_INFO_MODULE_ID_QTECH,		"qtech_ov5695", "qtech_ov5695", NULL},
};
#endif

DEFINE_MSM_MUTEX(msm_eeprom_mutex);
#ifdef CONFIG_COMPAT
static struct v4l2_file_operations msm_eeprom_v4l2_subdev_fops;
#endif

typedef int (*zte_read_eeprom_memory_func_t) (struct msm_eeprom_ctrl_t *,
			      struct msm_eeprom_memory_block_t *);


static int msm_eeprom_get_cmm_data(struct msm_eeprom_ctrl_t *e_ctrl,
				       struct msm_eeprom_cfg_data *cdata)
{
	int rc = 0;
	struct msm_eeprom_cmm_t *cmm_data = &e_ctrl->eboard_info->cmm_data;

	cdata->cfg.get_cmm_data.cmm_support = cmm_data->cmm_support;
	cdata->cfg.get_cmm_data.cmm_compression = cmm_data->cmm_compression;
	cdata->cfg.get_cmm_data.cmm_size = cmm_data->cmm_size;
	return rc;
}

static int eeprom_config_read_cal_data(struct msm_eeprom_ctrl_t *e_ctrl,
	struct msm_eeprom_cfg_data *cdata)
{
	int rc;

	/* check range */
	if (cdata->cfg.read_data.num_bytes >
		e_ctrl->cal_data.num_data) {
		CDBG("%s: Invalid size. exp %u, req %u\n", __func__,
			 e_ctrl->cal_data.num_data,
			 cdata->cfg.read_data.num_bytes);
		return -EINVAL;
	}
	if (!e_ctrl->cal_data.mapdata)
		return -EFAULT;
	rc = copy_to_user(cdata->cfg.read_data.dbuffer,
					  e_ctrl->cal_data.mapdata,
					  cdata->cfg.read_data.num_bytes);

	return rc;
}

static int msm_eeprom_config(struct msm_eeprom_ctrl_t *e_ctrl,
	void __user *argp)
{
	struct msm_eeprom_cfg_data *cdata =
		(struct msm_eeprom_cfg_data *)argp;
	int rc = 0;

	CDBG("%s E\n", __func__);
	switch (cdata->cfgtype) {
	case CFG_EEPROM_GET_INFO:
		CDBG("%s E CFG_EEPROM_GET_INFO\n", __func__);
		cdata->is_supported = e_ctrl->is_supported;
		memcpy(cdata->cfg.eeprom_name,
			   e_ctrl->eboard_info->eeprom_name,
			   sizeof(cdata->cfg.eeprom_name));
		break;
	case CFG_EEPROM_GET_CAL_DATA:
		CDBG("%s E CFG_EEPROM_GET_CAL_DATA\n", __func__);
		cdata->cfg.get_data.num_bytes =
			e_ctrl->cal_data.num_data;
		break;
	case CFG_EEPROM_READ_CAL_DATA:
		CDBG("%s E CFG_EEPROM_READ_CAL_DATA\n", __func__);
		rc = eeprom_config_read_cal_data(e_ctrl, cdata);
		break;
	case CFG_EEPROM_GET_MM_INFO:
		CDBG("%s E CFG_EEPROM_GET_MM_INFO\n", __func__);
		rc = msm_eeprom_get_cmm_data(e_ctrl, cdata);
		break;
	default:
		break;
	}

	CDBG("%s X rc: %d\n", __func__, rc);
	return rc;
}

static int msm_eeprom_get_subdev_id(struct msm_eeprom_ctrl_t *e_ctrl,
									void *arg)
{
	uint32_t *subdev_id = (uint32_t *)arg;

	CDBG("%s E\n", __func__);
	if (!subdev_id) {
		pr_err("%s failed\n", __func__);
		return -EINVAL;
	}
	*subdev_id = e_ctrl->subdev_id;
	CDBG("subdev_id %d\n", *subdev_id);
	CDBG("%s X\n", __func__);
	return 0;
}

static long msm_eeprom_subdev_ioctl(struct v4l2_subdev *sd,
									unsigned int cmd, void *arg)
{
	struct msm_eeprom_ctrl_t *e_ctrl = v4l2_get_subdevdata(sd);
	void __user *argp = (void __user *)arg;

	CDBG("%s E\n", __func__);
	CDBG("%s:%d a_ctrl %p argp %p\n", __func__, __LINE__, e_ctrl, argp);
	switch (cmd) {
	case VIDIOC_MSM_SENSOR_GET_SUBDEV_ID:
		return msm_eeprom_get_subdev_id(e_ctrl, argp);
	case VIDIOC_MSM_EEPROM_CFG:
		return msm_eeprom_config(e_ctrl, argp);
	default:
		return -ENOIOCTLCMD;
	}

	CDBG("%s X\n", __func__);
}

static struct msm_camera_i2c_fn_t msm_eeprom_cci_func_tbl = {
	.i2c_read = msm_camera_cci_i2c_read,
	.i2c_read_seq = msm_camera_cci_i2c_read_seq,
	.i2c_write = msm_camera_cci_i2c_write,
	.i2c_write_seq = msm_camera_cci_i2c_write_seq,
	.i2c_write_table = msm_camera_cci_i2c_write_table,
	.i2c_write_seq_table = msm_camera_cci_i2c_write_seq_table,
	.i2c_write_table_w_microdelay =
	msm_camera_cci_i2c_write_table_w_microdelay,
	.i2c_util = msm_sensor_cci_i2c_util,
	.i2c_poll = msm_camera_cci_i2c_poll,
};

static int msm_eeprom_open(struct v4l2_subdev *sd,
						   struct v4l2_subdev_fh *fh)
{
	int rc = 0;
	struct msm_eeprom_ctrl_t *e_ctrl =  v4l2_get_subdevdata(sd);

	CDBG("%s E\n", __func__);
	if (!e_ctrl) {
		pr_err("%s failed e_ctrl is NULL\n", __func__);
		return -EINVAL;
	}
	CDBG("%s X\n", __func__);
	return rc;
}

static int msm_eeprom_close(struct v4l2_subdev *sd,
							struct v4l2_subdev_fh *fh)
{
	int rc = 0;
	struct msm_eeprom_ctrl_t *e_ctrl =  v4l2_get_subdevdata(sd);

	CDBG("%s E\n", __func__);
	if (!e_ctrl) {
		pr_err("%s failed e_ctrl is NULL\n", __func__);
		return -EINVAL;
	}
	CDBG("%s X\n", __func__);
	return rc;
}

static const struct v4l2_subdev_internal_ops msm_eeprom_internal_ops = {
	.open = msm_eeprom_open,
	.close = msm_eeprom_close,
};


static struct msm_cam_clk_info cam_8974_clk_info[] = {
	[SENSOR_CAM_MCLK] = {"cam_src_clk", 23880000},
	[SENSOR_CAM_CLK] = {"cam_clk", 0},
};

static struct v4l2_subdev_core_ops msm_eeprom_subdev_core_ops = {
	.ioctl = msm_eeprom_subdev_ioctl,
};

static struct v4l2_subdev_ops msm_eeprom_subdev_ops = {
	.core = &msm_eeprom_subdev_core_ops,
};

static int msm_eeprom_get_dt_data(struct msm_eeprom_ctrl_t *e_ctrl)
{
	int rc = 0, i = 0;
	struct msm_eeprom_board_info *eb_info;
	struct msm_camera_power_ctrl_t *power_info =
			&e_ctrl->eboard_info->power_info;
	struct device_node *of_node = NULL;
	struct msm_camera_gpio_conf *gconf = NULL;
	uint16_t gpio_array_size = 0;
	uint16_t *gpio_array = NULL;

	eb_info = e_ctrl->eboard_info;
	if (e_ctrl->eeprom_device_type == MSM_CAMERA_SPI_DEVICE)
		of_node = e_ctrl->i2c_client.
				  spi_client->spi_master->dev.of_node;
	else if (e_ctrl->eeprom_device_type == MSM_CAMERA_PLATFORM_DEVICE)
		of_node = e_ctrl->pdev->dev.of_node;

	if (!of_node) {
		pr_err("%s: %d of_node is NULL\n", __func__, __LINE__);
		return -ENOMEM;
	}
	rc = msm_camera_get_dt_vreg_data(of_node, &power_info->cam_vreg,
									 &power_info->num_vreg);
	if (rc < 0)
		return rc;

	rc = msm_camera_get_dt_power_setting_data(of_node,
			power_info->cam_vreg, power_info->num_vreg,
			power_info);
	if (rc < 0)
		goto ERROR1;

	power_info->gpio_conf = kzalloc(sizeof(struct msm_camera_gpio_conf),
									GFP_KERNEL);
	if (!power_info->gpio_conf) {
		rc = -ENOMEM;
		goto ERROR2;
	}
	gconf = power_info->gpio_conf;
	gpio_array_size = of_gpio_count(of_node);
	CDBG("%s gpio count %d\n", __func__, gpio_array_size);

	if (gpio_array_size) {
		gpio_array = kcalloc(1, sizeof(uint16_t) * gpio_array_size,
							 GFP_KERNEL);
		if (!gpio_array) {
			goto ERROR3;
		}
		for (i = 0; i < gpio_array_size; i++) {
			gpio_array[i] = of_get_gpio(of_node, i);
			CDBG("%s gpio_array[%d] = %d\n", __func__, i,
				 gpio_array[i]);
		}

		rc = msm_camera_get_dt_gpio_req_tbl(of_node, gconf,
											gpio_array, gpio_array_size);
		if (rc < 0) {
			pr_err("%s failed %d\n", __func__, __LINE__);
			goto ERROR4;
		}

		rc = msm_camera_init_gpio_pin_tbl(of_node, gconf,
										  gpio_array, gpio_array_size);
		if (rc < 0) {
			pr_err("%s failed %d\n", __func__, __LINE__);
			goto ERROR4;
		}
		kfree(gpio_array);
	}

	return rc;
ERROR4:
	kfree(gpio_array);
ERROR3:
	kfree(power_info->gpio_conf);
ERROR2:
	kfree(power_info->cam_vreg);
ERROR1:
	kfree(power_info->power_setting);
	return rc;
}


static int msm_eeprom_cmm_dts(struct msm_eeprom_board_info *eb_info,
							  struct device_node *of_node)
{
	int rc = 0;
	struct msm_eeprom_cmm_t *cmm_data = &eb_info->cmm_data;

	cmm_data->cmm_support =
		of_property_read_bool(of_node, "qcom,cmm-data-support");
	if (!cmm_data->cmm_support)
		return -EINVAL;
	cmm_data->cmm_compression =
		of_property_read_bool(of_node, "qcom,cmm-data-compressed");
	if (!cmm_data->cmm_compression)
		CDBG("No MM compression data\n");

	rc = of_property_read_u32(of_node, "qcom,cmm-data-offset",
							  &cmm_data->cmm_offset);
	if (rc < 0)
		CDBG("No MM offset data\n");

	rc = of_property_read_u32(of_node, "qcom,cmm-data-size",
							  &cmm_data->cmm_size);
	if (rc < 0)
		CDBG("No MM size data\n");

	CDBG("cmm_support: cmm_compr %d, cmm_offset %d, cmm_size %d\n",
		 cmm_data->cmm_compression,
		 cmm_data->cmm_offset,
		 cmm_data->cmm_size);
	return 0;
}

#ifdef CONFIG_COMPAT
static int eeprom_config_read_cal_data32(struct msm_eeprom_ctrl_t *e_ctrl,
		void __user *arg)
{
	int rc;
	uint8_t *ptr_dest = NULL;
	struct msm_eeprom_cfg_data32 *cdata32 =
		(struct msm_eeprom_cfg_data32 *) arg;
	struct msm_eeprom_cfg_data cdata;

	cdata.cfgtype = cdata32->cfgtype;
	cdata.is_supported = cdata32->is_supported;
	cdata.cfg.read_data.num_bytes = cdata32->cfg.read_data.num_bytes;
	/* check range */
	if (cdata.cfg.read_data.num_bytes >
		e_ctrl->cal_data.num_data) {
		CDBG("%s: Invalid size. exp %u, req %u\n", __func__,
			 e_ctrl->cal_data.num_data,
			 cdata.cfg.read_data.num_bytes);
		return -EINVAL;
	}
	if (!e_ctrl->cal_data.mapdata)
		return -EFAULT;

	ptr_dest = (uint8_t *) compat_ptr(cdata32->cfg.read_data.dbuffer);

	rc = copy_to_user(ptr_dest, e_ctrl->cal_data.mapdata,
					  cdata.cfg.read_data.num_bytes);

	return rc;
}

static int msm_eeprom_config32(struct msm_eeprom_ctrl_t *e_ctrl,
							   void __user *argp)
{
	struct msm_eeprom_cfg_data *cdata = (struct msm_eeprom_cfg_data *)argp;
	int rc = 0;

	CDBG("%s E\n", __func__);
	switch (cdata->cfgtype) {
	case CFG_EEPROM_GET_INFO:
		CDBG("%s E CFG_EEPROM_GET_INFO\n", __func__);
		cdata->is_supported = e_ctrl->is_supported;
		memcpy(cdata->cfg.eeprom_name,
			   e_ctrl->eboard_info->eeprom_name,
			   sizeof(cdata->cfg.eeprom_name));
		break;
	case CFG_EEPROM_GET_CAL_DATA:
		CDBG("%s E CFG_EEPROM_GET_CAL_DATA\n", __func__);
		cdata->cfg.get_data.num_bytes =
			e_ctrl->cal_data.num_data;
		break;
	case CFG_EEPROM_READ_CAL_DATA:
		CDBG("%s E CFG_EEPROM_READ_CAL_DATA\n", __func__);
		rc = eeprom_config_read_cal_data32(e_ctrl, argp);
		break;
	default:
		break;
	}

	CDBG("%s X rc: %d\n", __func__, rc);
	return rc;
}

static long msm_eeprom_subdev_ioctl32(struct v4l2_subdev *sd,
									  unsigned int cmd, void *arg)
{
	struct msm_eeprom_ctrl_t *e_ctrl = v4l2_get_subdevdata(sd);
	void __user *argp = (void __user *)arg;

	CDBG("%s E\n", __func__);
	CDBG("%s:%d a_ctrl %p argp %p\n", __func__, __LINE__, e_ctrl, argp);
	switch (cmd) {
	case VIDIOC_MSM_SENSOR_GET_SUBDEV_ID:
		return msm_eeprom_get_subdev_id(e_ctrl, argp);
	case VIDIOC_MSM_EEPROM_CFG32:
		return msm_eeprom_config32(e_ctrl, argp);
	default:
		return -ENOIOCTLCMD;
	}

	CDBG("%s X\n", __func__);
}

static long msm_eeprom_subdev_do_ioctl32(
	struct file *file, unsigned int cmd, void *arg)
{
	struct video_device *vdev = video_devdata(file);
	struct v4l2_subdev *sd = vdev_to_v4l2_subdev(vdev);

	return msm_eeprom_subdev_ioctl32(sd, cmd, arg);
}

static long msm_eeprom_subdev_fops_ioctl32(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	return video_usercopy(file, cmd, arg, msm_eeprom_subdev_do_ioctl32);
}

#endif

/*
  * camera sensor module compatile
  *
  * by ZTE_YCM_20140728 yi.changming 000028
  */
static int lookupIndexByid(MODULE_Map_Table arr[], int len, uint16_t value)
{
	int i = 0;

	for (i = 0; i < len; i++) {
		if (arr[i].id == value) {
			return i;
		}
	}
	return ZTE_EEPROM_ERROR;
}
static void parse_module_name(struct msm_eeprom_ctrl_t *e_ctrl,
							MODULE_Map_Table *map, uint16_t len, uint16_t  sensor_module_id)
{
	int index = lookupIndexByid(map, len, sensor_module_id);

	if (index != -1) {
		e_ctrl->sensor_module_name = map[index].sensor_module_name;
		e_ctrl->chromtix_lib_name = map[index].chromtix_lib_name;
		e_ctrl->default_chromtix_lib_name = map[index].default_chromtix_lib_name;
		pr_err("ZTE_CAMERA:%s:%d:sensor_module_name = %s\n",
			__func__, __LINE__, e_ctrl->sensor_module_name);
	}
}

int imx214_slave_id[6] = {0xa0, 0xa4, 0xa6, 0xa8, 0xaa, 0xac};
static int imx214_read_eeprom_memory(struct msm_eeprom_ctrl_t *e_ctrl,
			      struct msm_eeprom_memory_block_t *block)
{
	int rc = 0;
	struct msm_eeprom_memory_map_t *emap = block->map;
	uint8_t *memptr = block->mapdata;
	uint16_t  sensor_module_id = 0;
	int i, j;

	CDBG("%s:E\n", __func__);
	if (!e_ctrl) {
		pr_err("%s e_ctrl is NULL", __func__);
		return -EINVAL;
	}

	for (j = 0; j < block->num_map; j++) {
		e_ctrl->i2c_client.addr_type = emap[j].mem.addr_t;
		e_ctrl->i2c_client.cci_client->sid = imx214_slave_id[j] >> 1;
		rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_read_seq(
					&(e_ctrl->i2c_client), emap[0].mem.addr,
					memptr, emap[j].mem.valid_size);
		if (rc < 0) {
			pr_err("%s:%d: read failed\n", __func__, __LINE__);
			return rc;
		}
		for (i = 0; i < emap[j].mem.valid_size; i++)
			CDBG("%s: block = %d:  data[%d]= %d\n", __func__, j, i, memptr[i]);
		memptr += emap[j].mem.valid_size;
	}
	sensor_module_id = block->mapdata[0];
	parse_module_name(e_ctrl, IMX214_MODULE_MAP,
			sizeof(IMX214_MODULE_MAP)/sizeof(MODULE_Map_Table), sensor_module_id);
	CDBG("%s:X\n", __func__);
	return rc;
}

#define  T4KB3_PAGE_LEN 64
#define  T4KB3_OTP_DATA_BEGIN_ADDR 0x3504

int T4KB3_enable_read_mode(struct msm_eeprom_ctrl_t *e_ctrl, int enable)
{
	int rc = 0;

	if (enable)
		rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x3500, 0x01,
			MSM_CAMERA_I2C_BYTE_DATA);
	else
		rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x3500, 0x00,
			MSM_CAMERA_I2C_BYTE_DATA);
	if (rc < 0) {
	   pr_err("%s:%d: read failed\n", __func__, __LINE__);
	}
	return rc;
}

int T4KB3_set_page(struct msm_eeprom_ctrl_t *e_ctrl, uint16_t page_number)
{
	int rc = 0;

	rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x3502, page_number,
		MSM_CAMERA_I2C_BYTE_DATA);
	if (rc < 0) {
	   pr_err("%s:%d:  failed\n", __func__, __LINE__);
	}
	return rc;
}

int T4KB3_check_start_acces(struct msm_eeprom_ctrl_t *e_ctrl)
{
	uint16_t temp;
	int rc = 0;
	int32_t i = 10;

	rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_read(&(e_ctrl->i2c_client), 0x3500, &temp,
								MSM_CAMERA_I2C_BYTE_DATA);
	if (rc < 0) {
		pr_err("%s:%d:  failed\n", __func__, __LINE__);
		return rc;
	}
	rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x3500, temp|0x80,
								MSM_CAMERA_I2C_BYTE_DATA);
	if (rc < 0) {
		pr_err("%s:%d:  failed\n", __func__, __LINE__);
		return rc;
	}
	usleep(20);
	while (i--) {
		rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_read(&(e_ctrl->i2c_client), 0x3500, &temp,
							MSM_CAMERA_I2C_BYTE_DATA);
		if (rc < 0) {
			pr_err("%s:%d:  failed\n", __func__, __LINE__);
			return rc;
		}
		if ((temp & 0x80) == 0)
			return 0;
		usleep(20);
	}
	return ZTE_EEPROM_ERROR;
}

int32_t T4KB3_read_page_data(struct msm_eeprom_ctrl_t *e_ctrl,
	struct msm_eeprom_memory_map_t *emap, uint8_t *buff)
{
	int rc = 0;

	e_ctrl->i2c_client.addr_type = emap->mem.addr_t;
	rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_read_seq(
			&(e_ctrl->i2c_client), T4KB3_OTP_DATA_BEGIN_ADDR,
			buff, T4KB3_PAGE_LEN);
	if (rc < 0) {
		pr_err("%s:%d: read failed\n", __func__, __LINE__);
	}
	return rc;
}

int T4KB3_read_page_page_data(struct msm_eeprom_ctrl_t *e_ctrl,
	struct msm_eeprom_memory_map_t *emap, int page, uint8_t *buff_data)
{
	int i = 0;
	int rc = 0;

	rc = T4KB3_set_page(e_ctrl, page);
	if (rc < 0) {
		pr_err("%s:%d:  failed\n", __func__, __LINE__);
		return rc;
	}

	rc = T4KB3_check_start_acces(e_ctrl);
	if (rc < 0) {
		pr_err("%s:%d:  failed\n", __func__, __LINE__);
		return rc;
	}

	rc = T4KB3_read_page_data(e_ctrl, emap, buff_data);
	if (rc < 0) {
		pr_err("%s:%d:  failed\n", __func__, __LINE__);
		return rc;
	}

	for (i = 0; i < T4KB3_PAGE_LEN; i++) {
		CDBG("%s:page = %d:  buff_data[%d]= %d\n", __func__, page, i, buff_data[i]);
	}

	 return rc;
}

static int T4KB3_read_eeprom_memory(struct msm_eeprom_ctrl_t *e_ctrl,
			      struct msm_eeprom_memory_block_t *block)
{
	int rc = 0;
	struct msm_eeprom_memory_map_t *emap = block->map;
	struct msm_eeprom_board_info *eb_info;
	uint8_t *memptr = block->mapdata;
	int i, sum = 0, valid_postion = -1;
	uint16_t  sensor_module_id = 0;
	uint8_t *page_p = NULL;

	if (!e_ctrl) {
		pr_err("%s e_ctrl is NULL", __func__);
		return -EINVAL;
	}

	eb_info = e_ctrl->eboard_info;
	e_ctrl->i2c_client.addr_type = MSM_CAMERA_I2C_WORD_ADDR;

	rc = T4KB3_enable_read_mode(e_ctrl, 1);
	if (rc < 0) {
		pr_err("%s:%d:  failed\n", __func__, __LINE__);
		return rc;
	}

	rc = T4KB3_read_page_page_data(e_ctrl, &(emap[0]), 0, memptr);
	if (rc < 0) {
		pr_err("%s:%d:  failed\n", __func__, __LINE__);
		return rc;
	}

	rc = T4KB3_read_page_page_data(e_ctrl, &(emap[1]), 1, memptr+T4KB3_PAGE_LEN);
	if (rc < 0) {
		pr_err("%s:%d:  failed\n", __func__, __LINE__);
		return rc;
	}

	rc = T4KB3_read_page_page_data(e_ctrl, &(emap[2]), 2, memptr+T4KB3_PAGE_LEN*2);
	if (rc < 0) {
		pr_err("%s:%d:  failed\n", __func__, __LINE__);
		return rc;
	}

	if (((*(memptr+1) | *(memptr+1+32)) & 0x2) == 0x2) {
		valid_postion = 1;
	} else if ((*(memptr+1) | *(memptr+1+32)) == 1) {
		valid_postion = 0;
	} else {
		pr_err("%s:%d: page 1 invalid\n", __func__, __LINE__);
		return ZTE_EEPROM_ERROR;
	}

	sum = 0;
	page_p = memptr + T4KB3_PAGE_LEN;
	for (i = valid_postion*16; i < valid_postion*16 + 15; i++) {
		sum  += (*(page_p + i) | *(page_p + i + 32));
	}
	if ((sum & 0xff) == (*(page_p+valid_postion*16+15) | *(page_p+valid_postion*16+32+15))) {
		sensor_module_id = *(page_p+valid_postion*16+2) | *(page_p+valid_postion*16+32+2);
		parse_module_name(e_ctrl, T4KB3_MODULE_MAP,
					sizeof(T4KB3_MODULE_MAP)/sizeof(MODULE_Map_Table), sensor_module_id);
	} else {
		pr_err("%s:%d: page 1 checksum failed sum = %x\n", __func__, __LINE__, sum);
		return ZTE_EEPROM_ERROR;
	}

	rc = T4KB3_enable_read_mode(e_ctrl, 0);
	if (rc < 0) {
		pr_err("%s:%d:  failed\n", __func__, __LINE__);
		return rc;
	}

	return rc;
}

int s5k3m2_slave_id = 0xa1;

static int s5k3m2_read_eeprom_memory(struct msm_eeprom_ctrl_t *e_ctrl,
			      struct msm_eeprom_memory_block_t *block)
{
	int rc = 0;
	struct msm_eeprom_memory_map_t *emap = block->map;
	uint8_t *memptr = block->mapdata;
	uint16_t  sensor_module_id = 0;
	int i, j;

	CDBG("%s:E\n", __func__);
	if (!e_ctrl) {
		pr_err("%s e_ctrl is NULL", __func__);
		return -EINVAL;
	}

	for (j = 0; j < block->num_map; j++) {
		e_ctrl->i2c_client.addr_type = emap[j].mem.addr_t;
		e_ctrl->i2c_client.cci_client->sid = s5k3m2_slave_id >> 1;
		rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_read_seq(
					&(e_ctrl->i2c_client), emap[j].mem.addr,
					memptr, emap[j].mem.valid_size);
		if (rc < 0) {
			pr_err("%s:%d: read failed\n", __func__, __LINE__);
			return rc;
		}
	for (i = 0; i < emap[j].mem.valid_size; i++)
		CDBG("%s: block = %d:  data[%d]= %d\n", __func__, j, i, memptr[i]);

		memptr += emap[j].mem.valid_size;
	}
	sensor_module_id = block->mapdata[2];
	pr_err("%s:sensor_module_id=%d", __func__, sensor_module_id);
	parse_module_name(e_ctrl, S5K3M2_MODULE_MAP,
			sizeof(S5K3M2_MODULE_MAP)/sizeof(MODULE_Map_Table), sensor_module_id);
	CDBG("%s:X\n", __func__);
	return rc;
}
/* end for 3m2 */
/* add for s5k5e8 eeprom begin by zte_cam_wqw_20151027 */
#ifdef CONFIG_BOARD_JASMINE
void s5k5e8_read_eeprom_init(struct msm_eeprom_ctrl_t *e_ctrl)
{
	e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x0A00, 0x04,
		MSM_CAMERA_I2C_BYTE_DATA);
	e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x0A02, 0x04,
		MSM_CAMERA_I2C_BYTE_DATA);
	e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x0A00, 0x01,
		MSM_CAMERA_I2C_BYTE_DATA);
	usleep(2000);
}

void s5k5e8_read_eeprom_end(struct msm_eeprom_ctrl_t *e_ctrl)
{
	e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x0A00, 0x04,
		MSM_CAMERA_I2C_BYTE_DATA);
	e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x0A00, 0x00,
		MSM_CAMERA_I2C_BYTE_DATA);
}
int32_t s5k5e8_check_module_info_group(struct msm_eeprom_ctrl_t *e_ctrl)
{
	uint16_t temp;
	int32_t group = Invlid_Group;

	e_ctrl->i2c_client.i2c_func_tbl->i2c_read(&(e_ctrl->i2c_client), 0x0a04, &temp,
			MSM_CAMERA_I2C_BYTE_DATA);
	CDBG("%s:temp=0x%X", __func__, temp);
	if (temp == 0x01) {
		CDBG("%s:AWB group 1 flag,temp=0x%X", __func__, temp);
		group = Group_One;
	} else {
		e_ctrl->i2c_client.i2c_func_tbl->i2c_read(&(e_ctrl->i2c_client), 0x0a19, &temp,
				MSM_CAMERA_I2C_BYTE_DATA);
		CDBG("%s:AWB group 2 flag,temp=0x%X", __func__, temp);
		if (temp == 0x01)
			group = Group_Two;
	}
	return group;
}
int32_t s5k5e8_check_module_AF_info_group(struct msm_eeprom_ctrl_t *e_ctrl)
{
	uint16_t temp;
	int32_t group = Invlid_Group;

	e_ctrl->i2c_client.i2c_func_tbl->i2c_read(&(e_ctrl->i2c_client), 0x0a04, &temp,
			MSM_CAMERA_I2C_BYTE_DATA);
	CDBG("%s:temp=0x%X\n", __func__, temp);
	if (temp == 0x01) {
		CDBG("%s:AF group 1 flag,temp=0x%X\n", __func__, temp);
		group = Group_Three;
	} else {
		e_ctrl->i2c_client.i2c_func_tbl->i2c_read(&(e_ctrl->i2c_client), 0x0a0e, &temp,
				MSM_CAMERA_I2C_BYTE_DATA);
		CDBG("%s:AF group 2 flag,temp=0x%X\n", __func__, temp);
		if (temp == 0x01)
			group = Group_Four;
	}
	return group;
}
#define  S5K5E8_LSC_SIZE 360
#define  S5K5E8_AWB_SIZE 0x13
#define  S5K5E8_AF_SIZE 4

static int s5k5e8_read_eeprom_memory(struct msm_eeprom_ctrl_t *e_ctrl,
									 struct msm_eeprom_memory_block_t *block)
{
	uint16_t temp;
	int rc = 0;
	struct msm_eeprom_memory_map_t *emap = block->map;
	struct msm_eeprom_board_info *eb_info;
	uint8_t *memptr = block->mapdata;
	uint16_t  sensor_module_id = 0;
	int32_t group_number;
	uint32_t module_id_addr;
	uint32_t af_flag_addr;
	uint32_t check_sum;
	uint8_t *buff_data;
	uint8_t lsc_flag;
	int num_byte;
	int i;

	if (!e_ctrl) {
		pr_err("%s e_ctrl is NULL", __func__);
		return -EINVAL;
	}

	pr_err("%s begin", __func__);
	eb_info = e_ctrl->eboard_info;
	e_ctrl->i2c_client.addr_type = MSM_CAMERA_I2C_WORD_ADDR;

	s5k5e8_read_eeprom_init(e_ctrl);

	group_number = s5k5e8_check_module_info_group(e_ctrl);
	switch (group_number) {
	case Group_One:
		module_id_addr = 0x0A05;
		pr_err("module_id_addr =0x%X\n", module_id_addr);
		break;
	case Group_Two:
		module_id_addr = 0x0A1A;
		pr_err("module_id_addr =0x%X\n", module_id_addr);
		break;
	default:
		break;
	}
	if (module_id_addr != 0) {
		e_ctrl->i2c_client.i2c_func_tbl->i2c_read(&(e_ctrl->i2c_client), module_id_addr, &sensor_module_id,
				MSM_CAMERA_I2C_BYTE_DATA);
		pr_err("sensor_module_id =0x%X\n", sensor_module_id);
		parse_module_name(e_ctrl, S5K5E8_MODULE_MAP,
				  sizeof(S5K5E8_MODULE_MAP) / sizeof(MODULE_Map_Table), sensor_module_id);
	}
/* LSC otp */
	e_ctrl->i2c_client.addr_type = emap[0].mem.addr_t;
	rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_read_seq(
				&(e_ctrl->i2c_client), emap[0].mem.addr,
				&lsc_flag, emap[0].mem.valid_size);
	if (lsc_flag == 0x01) {
		*memptr = 1;
		pr_err("LSC OTP read success\n");
	} else {
		*memptr = 0;
		pr_err("LSC OTP read failed\n");
	}
	memptr += 1;

/* AWB otp  */
	num_byte = S5K5E8_AWB_SIZE;
	buff_data = kzalloc(num_byte, GFP_KERNEL);
	memset(buff_data, 0, num_byte);

	e_ctrl->i2c_client.addr_type = emap[group_number].mem.addr_t;
	rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_read_seq(
				&(e_ctrl->i2c_client), emap[group_number].mem.addr,
				buff_data, emap[group_number].mem.valid_size);
	check_sum = 0;
	for (i = 0; i < S5K5E8_AWB_SIZE; i++) {
		check_sum += buff_data[i];
		pr_err("buff_data[%d]=0x%x\n", i, buff_data[i]);
	}
	check_sum = check_sum % 255 + 1;
	e_ctrl->i2c_client.i2c_func_tbl->i2c_read(&(e_ctrl->i2c_client), module_id_addr + S5K5E8_AWB_SIZE,
						 &temp,	MSM_CAMERA_I2C_BYTE_DATA);
	pr_err("%s:AWB checksum reg temp=0x%X", __func__, temp);

	if (check_sum == temp) {
		pr_err("AWB OTP read success\n");
		*memptr = 1;
		memptr += 1;
		for (i = 0; i < S5K5E8_AWB_SIZE; i++) {
			*memptr = buff_data[i];
			pr_err("*memptr=0x%x memptr=%p\n", *memptr, memptr);
			memptr += 1;
		}
	} else {
		*memptr = 0;
		memptr += 1;
		pr_err("AWB OTP read failed:group=%d\n", group_number);
	}

	kfree(buff_data);

/* AF otp */

	e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x0A00, 0x04,
							MSM_CAMERA_I2C_BYTE_DATA);
	e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x0A02, 0x0f,
							MSM_CAMERA_I2C_BYTE_DATA);
	e_ctrl->i2c_client.i2c_func_tbl->i2c_write(&(e_ctrl->i2c_client), 0x0A00, 0x01,
							MSM_CAMERA_I2C_BYTE_DATA);
	usleep(2000);

	group_number = s5k5e8_check_module_AF_info_group(e_ctrl);
	if (group_number == 0) {
		pr_err(" s5k5e8 AF OTP read failed\n");
		*memptr = 0;
		memptr += 1;
	} else {
		switch (group_number) {
		case Group_Three:
			af_flag_addr = 0x0A04;
			pr_err("af_flag_addr =0x%X\n", af_flag_addr);
			break;
		case Group_Four:
			af_flag_addr = 0x0A0E;
			pr_err("af_flag_addr=0x%X\n", af_flag_addr);
			break;
		default:
			break;
		}
		num_byte = S5K5E8_AF_SIZE;
		buff_data = kzalloc(num_byte, GFP_KERNEL);
		memset(buff_data, 0, num_byte);

		e_ctrl->i2c_client.addr_type = emap[group_number].mem.addr_t;
		rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_read_seq(
							&(e_ctrl->i2c_client), emap[group_number].mem.addr,
							buff_data, emap[group_number].mem.valid_size);
		check_sum = 0;
		for (i = 0; i < S5K5E8_AF_SIZE; i++) {
			check_sum += buff_data[i];
			pr_err("buff_data[%d]=0x%x\n", i, buff_data[i]);
		}
		check_sum = check_sum%255 + 1;
		e_ctrl->i2c_client.i2c_func_tbl->i2c_read(&(e_ctrl->i2c_client), af_flag_addr+S5K5E8_AF_SIZE+1, &temp,
								MSM_CAMERA_I2C_BYTE_DATA);
		pr_err("%s:AF checksum reg temp=0x%X", __func__, temp);

		if (check_sum == temp) {
			pr_err("AF OTP read success\n");
			*memptr = 1;
			memptr += 1;
			for (i = 0; i < S5K5E8_AF_SIZE; i++) {
				*memptr = buff_data[i];
				pr_err("*memptr=0x%x memptr=%p\n", *memptr, memptr);
				memptr += 1;
			}
		} else {
			*memptr = 0;
			memptr += 1;
			pr_err("AF OTP read failed:group=%d\n", group_number);
		}
		kfree(buff_data);
	}

	s5k5e8_read_eeprom_end(e_ctrl);
	pr_err("%s end\n", __func__);
	return rc;
}
#endif

int imx258_slave_id = 0xa1;

static int imx258_read_eeprom_memory(struct msm_eeprom_ctrl_t *e_ctrl,
			      struct msm_eeprom_memory_block_t *block)
{
	int rc = 0;
	struct msm_eeprom_memory_map_t *emap = block->map;
	uint8_t *memptr = block->mapdata;
	uint16_t  sensor_module_id = 0;
	int i, j;

	CDBG("%s:E\n", __func__);
	if (!e_ctrl) {
		pr_err("%s e_ctrl is NULL", __func__);
		return -EINVAL;
	}

	for (j = 0; j < block->num_map; j++) {
		e_ctrl->i2c_client.addr_type = emap[j].mem.addr_t;
		e_ctrl->i2c_client.cci_client->sid = imx258_slave_id >> 1;
		rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_read_seq(
								&(e_ctrl->i2c_client), emap[j].mem.addr,
								memptr, emap[j].mem.valid_size);
		if (rc < 0) {
			pr_err("%s:%d: read failed\n", __func__, __LINE__);
			return rc;
		}
		for (i = 0; i < emap[j].mem.valid_size; i++)
			CDBG("%s: block = %d:  data[%d]= %d\n", __func__, j, i, memptr[i]);

		memptr += emap[j].mem.valid_size;

	}
	sensor_module_id = block->mapdata[2];
	pr_err("%s:sensor_module_id=%d", __func__, sensor_module_id);
	parse_module_name(e_ctrl, IMX258_MODULE_MAP,
	sizeof(IMX258_MODULE_MAP)/sizeof(MODULE_Map_Table), sensor_module_id);
	CDBG("%s:X\n", __func__);
	return rc;
}
/* only support qtech && kerr for devjon*/
#ifdef CONFIG_BOARD_GEVJON
int ov5695_slave_id = 0xa0;

void ov5695_read_eeprom_end(struct msm_eeprom_ctrl_t *e_ctrl)
{

}

int32_t ov5695_check_module_info_group(struct msm_eeprom_ctrl_t *e_ctrl)
{
	uint16_t temp;

	e_ctrl->i2c_client.i2c_func_tbl->i2c_read(&(e_ctrl->i2c_client), 0x700C, &temp,
			MSM_CAMERA_I2C_BYTE_DATA);
	CDBG("HWD %s:temp=0x%X", __func__, temp);
	if ((temp&0xC0) == 0x40) {
		return Group_One;
	} else if ((temp&0x30) == 0x10) {
		return Group_Two;
	} else if ((temp&0x0c) == 0x04) {
		return Group_Three;
	}
	return Invlid_Group;
}

static int ov5695_read_eeprom_memory(struct msm_eeprom_ctrl_t *e_ctrl,
			      struct msm_eeprom_memory_block_t *block)
{

	int rc = 0;
	struct msm_eeprom_memory_map_t *emap = block->map;
	struct msm_eeprom_board_info *eb_info;
	uint8_t *memptr = block->mapdata;
	uint16_t  sensor_module_id = 0;
	int i, j;

	if (!e_ctrl) {
		pr_err("%s e_ctrl is NULL", __func__);
		return -EINVAL;
	}
	pr_err("%s begin", __func__);
	eb_info = e_ctrl->eboard_info;
	e_ctrl->i2c_client.addr_type = MSM_CAMERA_I2C_BYTE_ADDR;
	e_ctrl->i2c_client.i2c_func_tbl->i2c_read(&(e_ctrl->i2c_client), 0, &sensor_module_id,
							MSM_CAMERA_I2C_BYTE_DATA);
	pr_err("%s:sensor_module_id=%d\n", __func__, sensor_module_id);
	parse_module_name(e_ctrl, OV5695_MODULE_MAP,
		sizeof(OV5695_MODULE_MAP)/sizeof(MODULE_Map_Table), sensor_module_id);
	for (j = 0; j < block->num_map; j++) {
		e_ctrl->i2c_client.cci_client->sid = emap[j].mem.addr >> 1;
		rc = e_ctrl->i2c_client.i2c_func_tbl->i2c_read_seq(
					&(e_ctrl->i2c_client), 0,
					memptr, emap[j].mem.valid_size);
		if (rc < 0) {
			pr_err("%s:%d: read failed\n", __func__, __LINE__);
			return rc;
		}
		for (i = 0; i < emap[j].mem.valid_size; i++)
			CDBG("%s: block = %d:  data[%d]= %d\n", __func__, j, i, memptr[i]);

		memptr += emap[j].mem.valid_size;
	}
	pr_err("%s end", __func__);
	return rc;
}
#endif

static int zte_eeprom_generate_map(struct device_node *of,
				       struct msm_eeprom_memory_block_t *data)
{
	int i, rc = 0;
	char property[PROPERTY_MAXSIZE];
	uint32_t count = 6;
	struct msm_eeprom_memory_map_t *map;

	snprintf(property, PROPERTY_MAXSIZE, "zte,num-blocks");
	rc = of_property_read_u32(of, property, &data->num_map);
	CDBG("%s: %s %d\n", __func__, property, data->num_map);
	if (rc < 0) {
		pr_err("%s failed rc %d\n", __func__, rc);
		return rc;
	}
	map = kzalloc((sizeof(*map) * data->num_map), GFP_KERNEL);
	if (!map) {
		return -ENOMEM;
	}
	data->map = map;
	for (i = 0; i < data->num_map; i++) {
		snprintf(property, PROPERTY_MAXSIZE, "zte,mem%d", i);
		rc = of_property_read_u32_array(of, property,
				(uint32_t *) &map[i].mem, count);
		if (rc < 0) {
			pr_err("%s failed %d\n", __func__, __LINE__);
			goto ERROR;
		}
		data->num_data += map[i].mem.valid_size;
	}
	CDBG("%s num_bytes %d\n", __func__, data->num_data);
	data->mapdata = kzalloc(data->num_data, GFP_KERNEL);
	if (!data->mapdata) {
		rc = -ENOMEM;
		goto ERROR;
	}
	return rc;
ERROR:
	kfree(data->map);
	memset(data, 0, sizeof(*data));
	return rc;
}

static const struct of_device_id zte_eeprom_dt_match[] = {
	{ .compatible = "zte,eeprom-imx214", .data = (void *)imx214_read_eeprom_memory },
	{ .compatible = "zte,eeprom-t4kb3", .data = (void *)T4KB3_read_eeprom_memory },
	{ .compatible = "zte,eeprom-s5k3m2", .data = (void *)s5k3m2_read_eeprom_memory },
#ifdef CONFIG_BOARD_JASMINE
	{ .compatible = "zte,eeprom-s5k5e8", .data = (void *)s5k5e8_read_eeprom_memory },
#endif
/*
* add ov5695 driver
*/
#ifdef CONFIG_BOARD_GEVJON
	{ .compatible = "zte,eeprom-ov5695", .data = (void *)ov5695_read_eeprom_memory },
#endif
	{ .compatible = "zte,eeprom-imx258", .data = (void *)imx258_read_eeprom_memory },
	{ }
};

static int zte_eeprom_platform_probe(struct platform_device *pdev)
{
	int rc = 0;
	int j = 0;
	uint32_t temp;
	struct msm_camera_cci_client *cci_client = NULL;
	struct msm_eeprom_ctrl_t *e_ctrl = NULL;
	struct msm_eeprom_board_info *eb_info = NULL;
	struct device_node *of_node = pdev->dev.of_node;
	struct msm_camera_power_ctrl_t *power_info = NULL;
	const struct of_device_id *match;
	zte_read_eeprom_memory_func_t zte_read_eeprom_memory = NULL;

	CDBG("%s E\n", __func__);
	match = of_match_device(zte_eeprom_dt_match, &pdev->dev);
	zte_read_eeprom_memory = (zte_read_eeprom_memory_func_t)match->data;
	e_ctrl = kzalloc(sizeof(*e_ctrl), GFP_KERNEL);
	if (!e_ctrl) {
		return -ENOMEM;
	}
	e_ctrl->eeprom_v4l2_subdev_ops = &msm_eeprom_subdev_ops;
	e_ctrl->eeprom_mutex = &msm_eeprom_mutex;
	e_ctrl->is_supported = 0;
	if (!of_node) {
		pr_err("%s dev.of_node NULL\n", __func__);
		return -EINVAL;
	}
	rc = of_property_read_u32(of_node, "cell-index",
		&pdev->id);
	CDBG("cell-index %d, rc %d\n", pdev->id, rc);
	if (rc < 0) {
		pr_err("failed rc %d\n", rc);
		return rc;
	}
	e_ctrl->subdev_id = pdev->id;
	rc = of_property_read_u32(of_node, "qcom,cci-master",
		&e_ctrl->cci_master);
	CDBG("qcom,cci-master %d, rc %d\n", e_ctrl->cci_master, rc);
	if (rc < 0) {
		pr_err("%s failed rc %d\n", __func__, rc);
		return rc;
	}
	rc = of_property_read_u32(of_node, "qcom,slave-addr",
		&temp);
	if (rc < 0) {
		pr_err("%s failed rc %d\n", __func__, rc);
		return rc;
	}
	e_ctrl->pdev = pdev;
	e_ctrl->eeprom_device_type = MSM_CAMERA_PLATFORM_DEVICE;
	e_ctrl->i2c_client.i2c_func_tbl = &msm_eeprom_cci_func_tbl;
	e_ctrl->i2c_client.cci_client = kzalloc(sizeof(
		struct msm_camera_cci_client), GFP_KERNEL);
	if (!e_ctrl->i2c_client.cci_client) {
		return -ENOMEM;
	}
	e_ctrl->eboard_info = kzalloc(sizeof(
		struct msm_eeprom_board_info), GFP_KERNEL);
	if (!e_ctrl->eboard_info) {
		rc = -ENOMEM;
		goto cciclient_free;
	}
	eb_info = e_ctrl->eboard_info;
	power_info = &eb_info->power_info;
	eb_info->i2c_slaveaddr = temp;
	power_info->clk_info = cam_8974_clk_info;
	power_info->clk_info_size = ARRAY_SIZE(cam_8974_clk_info);
	power_info->dev = &pdev->dev;
	CDBG("qcom,slave-addr = 0x%X\n", eb_info->i2c_slaveaddr);
	cci_client = e_ctrl->i2c_client.cci_client;
	cci_client->cci_subdev = msm_cci_get_subdev();
	cci_client->cci_i2c_master = e_ctrl->cci_master;
	cci_client->sid = eb_info->i2c_slaveaddr >> 1;
	cci_client->retries = 3;
	cci_client->id_map = 0;
	cci_client->i2c_freq_mode = I2C_FAST_MODE;
	rc = of_property_read_string(of_node, "qcom,eeprom-name",
		&eb_info->eeprom_name);
	CDBG("%s qcom,eeprom-name %s, rc %d\n", __func__,
		eb_info->eeprom_name, rc);
	if (rc < 0) {
		pr_err("%s failed %d\n", __func__, __LINE__);
		goto board_free;
	}
	rc = msm_eeprom_cmm_dts(e_ctrl->eboard_info, of_node);
	if (rc < 0)
		CDBG("%s MM data miss:%d\n", __func__, __LINE__);
	rc = msm_eeprom_get_dt_data(e_ctrl);
	if (rc)
		goto board_free;
	rc = zte_eeprom_generate_map(of_node, &e_ctrl->cal_data);
	if (rc < 0)
		goto board_free;
	rc = msm_camera_power_up(power_info, e_ctrl->eeprom_device_type,
		&e_ctrl->i2c_client);
	if (rc) {
		pr_err("failed rc %d\n", rc);
		goto memdata_free;
	}

	rc = zte_read_eeprom_memory(e_ctrl, &e_ctrl->cal_data);
	if (rc < 0) {
		pr_err("%s read_eeprom_memory failed\n", __func__);
		goto power_down;
	}
	for (j = 0; j < e_ctrl->cal_data.num_data; j++)
		CDBG("memory_data[%d] = 0x%X\n", j,
			e_ctrl->cal_data.mapdata[j]);
	e_ctrl->is_supported = 1;
	rc = msm_camera_power_down(power_info, e_ctrl->eeprom_device_type,
		&e_ctrl->i2c_client);
	if (rc) {
		pr_err("failed rc %d\n", rc);
		goto memdata_free;
	}
	v4l2_subdev_init(&e_ctrl->msm_sd.sd,
		e_ctrl->eeprom_v4l2_subdev_ops);
	v4l2_set_subdevdata(&e_ctrl->msm_sd.sd, e_ctrl);
	platform_set_drvdata(pdev, &e_ctrl->msm_sd.sd);
	e_ctrl->msm_sd.sd.internal_ops = &msm_eeprom_internal_ops;
	e_ctrl->msm_sd.sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	snprintf(e_ctrl->msm_sd.sd.name,
		ARRAY_SIZE(e_ctrl->msm_sd.sd.name), "msm_eeprom");
	media_entity_init(&e_ctrl->msm_sd.sd.entity, 0, NULL, 0);
	e_ctrl->msm_sd.sd.entity.type = MEDIA_ENT_T_V4L2_SUBDEV;
	e_ctrl->msm_sd.sd.entity.group_id = MSM_CAMERA_SUBDEV_EEPROM;
	msm_sd_register(&e_ctrl->msm_sd);
#ifdef CONFIG_COMPAT
	msm_eeprom_v4l2_subdev_fops = v4l2_subdev_fops;
	msm_eeprom_v4l2_subdev_fops.compat_ioctl32 =
		msm_eeprom_subdev_fops_ioctl32;
	e_ctrl->msm_sd.sd.devnode->fops = &msm_eeprom_v4l2_subdev_fops;
#endif
	e_ctrl->is_supported = (e_ctrl->is_supported << 1) | 1;
	CDBG("%s X\n", __func__);
	return rc;
power_down:
	msm_camera_power_down(power_info, e_ctrl->eeprom_device_type,
		&e_ctrl->i2c_client);
memdata_free:
	kfree(e_ctrl->cal_data.mapdata);
	kfree(e_ctrl->cal_data.map);
board_free:
	kfree(e_ctrl->eboard_info);
cciclient_free:
	kfree(e_ctrl->i2c_client.cci_client);
	kfree(e_ctrl);
	return rc;
}

static int zte_eeprom_platform_remove(struct platform_device *pdev)
{
	struct v4l2_subdev *sd = platform_get_drvdata(pdev);
	struct msm_eeprom_ctrl_t  *e_ctrl;

	if (!sd) {
		pr_err("%s: Subdevice is NULL\n", __func__);
		return 0;
	}

	e_ctrl = (struct msm_eeprom_ctrl_t *)v4l2_get_subdevdata(sd);
	if (!e_ctrl) {
		pr_err("%s: eeprom device is NULL\n", __func__);
		return 0;
	}

	kfree(e_ctrl->i2c_client.cci_client);
	kfree(e_ctrl->cal_data.mapdata);
	kfree(e_ctrl->cal_data.map);
	if (e_ctrl->eboard_info) {
		kfree(e_ctrl->eboard_info->power_info.gpio_conf);
		kfree(e_ctrl->eboard_info);
	}
	kfree(e_ctrl);
	return 0;
}

static struct platform_driver zte_eeprom_platform_driver = {
	.driver = {
		.name = "zte,eeprom",
		.owner = THIS_MODULE,
		.of_match_table = zte_eeprom_dt_match,
	},
	.remove = zte_eeprom_platform_remove,
};

static int __init zte_eeprom_init_module(void)
{
	int rc = 0;

	CDBG("%s E\n", __func__);
	rc = platform_driver_probe(&zte_eeprom_platform_driver,
		zte_eeprom_platform_probe);
	CDBG("%s:%d platform rc %d\n", __func__, __LINE__, rc);
	return rc;
}

static void __exit zte_eeprom_exit_module(void)
{
	platform_driver_unregister(&zte_eeprom_platform_driver);

}

module_init(zte_eeprom_init_module);
module_exit(zte_eeprom_exit_module);
MODULE_DESCRIPTION("MSM EEPROM driver");
MODULE_LICENSE("GPL v2");
