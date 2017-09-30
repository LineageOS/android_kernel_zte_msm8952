/* Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/module.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/kobject.h>
#include "msm_led_flash.h"

#include "msm_camera_io_util.h"
#include "../cci/msm_cci.h"
#include "../msm_sensor.h"
#include "../cci/msm_cci.h"
#include <linux/debugfs.h>


#define FLASH_NAME "pmic"

#define CONFIG_MSMB_CAMERA_DEBUG
#undef CDBG
#ifdef CONFIG_MSMB_CAMERA_DEBUG
#define CDBG(fmt, args...) pr_err(fmt, ##args)
#else
#define CDBG(fmt, args...) do { } while (0)
#endif
#define TEST_TORCH 1
#ifdef TEST_TORCH
struct kobject *soc_kobj = NULL;
#endif
static struct msm_led_flash_ctrl_t fctrl;
static struct i2c_driver lm3646_i2c_driver;
static int32_t msm_led_lm3646_get_dt_data(struct device_node *of_node,
		struct msm_led_flash_ctrl_t *fctrl);
static inline int of_gpio_count(struct device_node *np);
int msm_camera_get_dt_gpio_req_tbl(struct device_node *of_node,
	struct msm_camera_gpio_conf *gconf, uint16_t *gpio_array,
	uint16_t gpio_array_size);
int msm_camera_get_dt_gpio_set_tbl(struct device_node *of_node,
	struct msm_camera_gpio_conf *gconf, uint16_t *gpio_array,
	uint16_t gpio_array_size);
static  int of_get_gpio(struct device_node *np, int index);

int msm_camera_init_gpio_pin_tbl(struct device_node *of_node,
	struct msm_camera_gpio_conf *gconf, uint16_t *gpio_array,
	uint16_t gpio_array_size);

static int msm_flash_lm3646_led_init(struct msm_led_flash_ctrl_t *fctrl);
static int msm_flash_lm3646_led_low(struct msm_led_flash_ctrl_t *fctrl, struct msm_flash_cfg_data_t *flash_data);
static int msm_flash_lm3646_led_high(struct msm_led_flash_ctrl_t *fctrl);
static int msm_flash_lm3646_led_off(struct msm_led_flash_ctrl_t *fctrl);




static struct msm_camera_i2c_reg_array lm3646_init_array[] = {
};

static struct msm_camera_i2c_reg_array lm3646_off_array[] = {
	{0x01, 0xE0},
};

static struct msm_camera_i2c_reg_array lm3646_release_array[] = {
	{0x01, 0xE0},
};

static struct msm_camera_i2c_reg_array lm3646_low_array[] = {
	{0x01, 0xE2},
	{0x05, 0x7f},
	{0x07, 0x3f},
};

static struct msm_camera_i2c_reg_array lm3646_high_array[] = {
	{0x01,  0xE3},
	{0x04,  0x5f},
	{0x05,  0x7f},
	{0x06,  0x3f},
};

static struct msm_sensor_power_setting lm3646_flash_power_setting[] = {
	{
		.seq_type = SENSOR_VREG,
		.seq_val = CAM_VIO,
		.config_val = 0,
		.delay = 2,
		},
	};

static void __exit msm_flash_lm3646_i2c_remove(void)
{
	i2c_del_driver(&lm3646_i2c_driver);
}

static const struct of_device_id lm3646_trigger_dt_match[] = {
	{.compatible = FLASH_NAME, .data = &fctrl},
	{}
};

MODULE_DEVICE_TABLE(of, lm3646_trigger_dt_match);

static const struct i2c_device_id flash_i2c_id[] = {
	{FLASH_NAME, (kernel_ulong_t)&fctrl},
	{ }
};

static const struct i2c_device_id lm3646_i2c_id[] = {
	{FLASH_NAME, (kernel_ulong_t)&fctrl},
	{ }
};

#ifdef TEST_TORCH
static ssize_t sysfs_my_torch(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	CDBG("flash %s,%d\n", __func__, __LINE__);
	msm_flash_lm3646_led_init(&fctrl);
	msm_flash_lm3646_led_low(&fctrl, NULL);
	return 0;
};
static ssize_t sysfs_my_off(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	CDBG("flash %s,%d\n", __func__, __LINE__);
	msm_flash_lm3646_led_off(&fctrl);
	return 0;
};
static ssize_t sysfs_my_flash(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	CDBG("flash %s,%d\n", __func__, __LINE__);
	msm_flash_lm3646_led_init(&fctrl);
	msm_flash_lm3646_led_high(&fctrl);
	return 0;
};
static struct kobj_attribute sysfs_torch = __ATTR(open_torch, S_IRUGO, sysfs_my_torch, NULL);
static struct kobj_attribute sysfs_off = __ATTR(flash_off, S_IRUGO, sysfs_my_off, NULL);
static struct kobj_attribute sysfs_flash = __ATTR(open_flash, S_IRUGO, sysfs_my_flash, NULL);


static struct attribute *flash_sysfs[] = {
		&sysfs_torch.attr,
		&sysfs_off.attr,
		&sysfs_flash.attr,
		NULL,
	};
static struct attribute_group flash_attr_group = {
	.attrs = flash_sysfs,
	};
#endif
static int32_t msm_led_get_dt_vreg_data(struct device_node *of_node, struct camera_vreg_t *cam_vreg)
{
	int32_t rc = 0, i = 0;
	uint32_t count = 0;

	if (of_node)
		pr_info("%s: %d %s", __func__, __LINE__, of_node->name);
	else
		return -EINVAL;
	count = of_property_count_strings(of_node, "qcom,cam-vreg-name");
	CDBG("%s qcom,cam-vreg-name count %d\n", __func__, count);

	if (!count)
		return 0;
	rc = of_property_read_string_index(of_node, "qcom,cam-vreg-name", i,
			&cam_vreg->reg_name);
	pr_info("%s reg_nam = %s\n", __func__, cam_vreg->reg_name);
	if (rc < 0) {
		pr_err("%s failed %d\n", __func__, __LINE__);
		return rc;
	}

	return rc;
}

static int32_t msm_led_lm3646_get_dt_data(struct device_node *of_node,
		struct msm_led_flash_ctrl_t *fctrl)
{
	int32_t rc = 0, i = 0;
	struct msm_camera_gpio_conf *gconf = NULL;
	struct device_node *flash_src_node = NULL;
	struct msm_camera_sensor_board_info *flashdata = NULL;
	struct msm_camera_power_ctrl_t *power_info = NULL;
	uint32_t count = 0;
	uint16_t *gpio_array = NULL;
	uint16_t gpio_array_size = 0;
	uint32_t id_info[3];

	CDBG("%s:called\n", __func__);

	if (!of_node) {
		pr_err("of_node NULL\n");
		return -EINVAL;
	}

	fctrl->flashdata = kzalloc(sizeof(
		struct msm_camera_sensor_board_info),
		GFP_KERNEL);
	if (!fctrl->flashdata) {
		pr_err("%s failed %d\n", __func__, __LINE__);
		return -ENOMEM;
	}

	flashdata = fctrl->flashdata;
	power_info = &flashdata->power_info;

	rc = of_property_read_u32(of_node, "cell-index", &fctrl->subdev_id);
	if (rc < 0) {
		pr_err("failed\n");
		rc = -EINVAL;
		goto ERROR1;
	}

	CDBG("subdev id %d\n", fctrl->subdev_id);

	rc = of_property_read_string(of_node, "label",
		&flashdata->sensor_name);
	CDBG("%s label %s, rc= %d\n", __func__,
		flashdata->sensor_name, rc);
	if (rc < 0) {
		pr_err("%s failed %d\n", __func__, __LINE__);
		goto ERROR1;
	}

	rc = of_property_read_u32(of_node, "qcom,cci-master",
		&fctrl->cci_i2c_master);
	CDBG("%s qcom,cci-master= %d, rc= %d\n", __func__, fctrl->cci_i2c_master,
		rc);
	if (rc < 0) {
		/* Set default master 0 */
		fctrl->cci_i2c_master = MASTER_0;
		rc = 0;
	}

	fctrl->pinctrl_info.use_pinctrl = false;
	fctrl->pinctrl_info.use_pinctrl = of_property_read_bool(of_node,
						"qcom,enable_pinctrl");
	if (of_get_property(of_node, "qcom,flash-source", &count)) {
		count /= sizeof(uint32_t);
		CDBG("count %d\n", count);
		if (count > MAX_LED_TRIGGERS) {
			pr_err("failed\n");
			rc = -EINVAL;
			goto ERROR1;
		}
		for (i = 0; i < count; i++) {
			flash_src_node = of_parse_phandle(of_node,
				"qcom,flash-source", i);
			if (!flash_src_node) {
				pr_err("flash_src_node NULL\n");
				continue;
			}

			rc = of_property_read_string(flash_src_node,
				"linux,default-trigger",
				&fctrl->flash_trigger_name[i]);
			if (rc < 0) {
				pr_err("failed\n");
				of_node_put(flash_src_node);
				continue;
			}

			CDBG("default trigger %s\n",
				 fctrl->flash_trigger_name[i]);

			rc = of_property_read_u32(flash_src_node,
				"qcom,max-current",
				&fctrl->flash_op_current[i]);
			if (rc < 0) {
				pr_err("failed rc %d\n", rc);
				of_node_put(flash_src_node);
				continue;
			}

			of_node_put(flash_src_node);

			CDBG("max_current[%d] %d\n",
				i, fctrl->flash_op_current[i]);

			led_trigger_register_simple(
				fctrl->flash_trigger_name[i],
				&fctrl->flash_trigger[i]);
		}

	} else { /*Handle LED Flash Ctrl by GPIO*/
		power_info->gpio_conf =
			 kzalloc(sizeof(struct msm_camera_gpio_conf),
				 GFP_KERNEL);
		if (!power_info->gpio_conf) {
			pr_err("%s failed %d\n", __func__, __LINE__);
			rc = -ENOMEM;
			goto ERROR1;
		}
		gconf = power_info->gpio_conf;

		gpio_array_size = of_gpio_count(of_node);
		CDBG("%s gpio count %d\n", __func__, gpio_array_size);


		if (gpio_array_size) {
			gpio_array = kcalloc(gpio_array_size, sizeof(uint16_t), GFP_KERNEL);
			if (!gpio_array) {
				pr_err("%s failed %d\n", __func__, __LINE__);
				rc = -ENOMEM;
				goto ERROR4;
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
				kfree(gpio_array);
				goto ERROR4;
			}

			rc = msm_camera_get_dt_gpio_set_tbl(of_node, gconf,
				gpio_array, gpio_array_size);
			if (rc < 0) {
				pr_err("%s failed %d\n", __func__, __LINE__);
				kfree(gpio_array);
				goto ERROR4;
			}

			rc = msm_camera_init_gpio_pin_tbl(of_node, gconf,
				gpio_array, gpio_array_size);
			if (rc < 0) {
				pr_err("%s failed %d\n", __func__, __LINE__);
				kfree(gpio_array);
				goto ERROR4;
			}
			kfree(gpio_array);
		}

		/* Read the max current for an LED if present */
		if (of_get_property(of_node, "qcom,max-current", &count)) {
			count /= sizeof(uint32_t);

			if (count > MAX_LED_TRIGGERS) {
				pr_err("failed\n");
				rc = -EINVAL;
				goto ERROR4;
			}

			fctrl->flash_num_sources = count;
			fctrl->torch_num_sources = count;

			rc = of_property_read_u32_array(of_node,
				"qcom,max-current",
				fctrl->flash_max_current, count);
			if (rc < 0) {
				pr_err("%s failed %d\n", __func__, __LINE__);
				rc = -EINVAL;
				goto ERROR4;
			}

			for (; count < MAX_LED_TRIGGERS; count++)
				fctrl->flash_max_current[count] = 0;

			for (count = 0; count < MAX_LED_TRIGGERS; count++)
				fctrl->torch_max_current[count] =
					fctrl->flash_max_current[count] >> 1;
		}

		/* Read the max duration for an LED if present */
		if (of_get_property(of_node, "qcom,max-duration", &count)) {
			count /= sizeof(uint32_t);

			if (count > MAX_LED_TRIGGERS) {
				pr_err("failed\n");
				rc = -EINVAL;
				goto ERROR4;
			}

			rc = of_property_read_u32_array(of_node,
				"qcom,max-duration",
				fctrl->flash_max_duration, count);
			if (rc < 0) {
				pr_err("%s failed %d\n", __func__, __LINE__);
				goto ERROR4;
			}

			for (; count < MAX_LED_TRIGGERS; count++)
				fctrl->flash_max_duration[count] = 0;
		}

		flashdata->slave_info =
			kzalloc(sizeof(struct msm_camera_slave_info),
				GFP_KERNEL);
		if (!flashdata->slave_info) {
			pr_err("%s failed %d\n", __func__, __LINE__);
			rc = -ENOMEM;
			goto ERROR4;
		}

		rc = of_property_read_u32_array(of_node, "qcom,slave-id",
			id_info, 3);
		if (rc < 0) {
			pr_err("%s failed %d\n", __func__, __LINE__);
			rc = -ENOMEM;
			goto ERROR5;
		}
		 msm_led_get_dt_vreg_data(of_node, &fctrl->cam_vreg);
		/*printk("%s %d %d",__func__,__LINE__,j);*/
		/*msm_lm3646_get_dt_vreg_data(of_node, &(fctrl->flashdata->power_info.cam_vreg));*/
		/*printk("%s: %d %u",__func__,__LINE__,fctrl->flashdata->slave_info->sensor_slave_addr);*/
		fctrl->flashdata->slave_info->sensor_slave_addr = id_info[0];
		fctrl->flashdata->slave_info->sensor_id_reg_addr = id_info[1];
		fctrl->flashdata->slave_info->sensor_id = id_info[2];
		/*printk("%s: %d %u",__func__,__LINE__,fctrl->flashdata->slave_info->sensor_slave_addr);*/
		/*printk("%s: %d  id_infor[0]= %u",__func__,__LINE__,id_info[0]);*/
		/*printk("%s: %d  id_infor[1]= %u",__func__,__LINE__,id_info[1]);*/
		/*printk("%s: %d  id_infor[2]= %u",__func__,__LINE__,id_info[2]);*/
ERROR5:
		kfree(flashdata->slave_info);
ERROR4:
		kfree(gconf);
	}
ERROR1:
		kfree(fctrl->flashdata);
	return rc;
}

static int msm_flash_lm3646_i2c_probe(struct i2c_client *client,
		const struct i2c_device_id *id)
{
	CDBG("%s,%d\n", __func__, __LINE__);

	if (!id) {
		pr_err("msm_flash_lm3646_i2c_probe: id is NULL");
		id = lm3646_i2c_id;
	}
	CDBG("%s,%d\n", __func__, __LINE__);
	return msm_flash_i2c_probe(client, id);
}

static struct i2c_driver lm3646_i2c_driver = {
	.id_table = lm3646_i2c_id,
	.probe  = msm_flash_lm3646_i2c_probe,
	.remove = __exit_p(msm_flash_lm3646_i2c_remove),
	.driver = {
		.name = FLASH_NAME,
		.owner = THIS_MODULE,
		.of_match_table = lm3646_trigger_dt_match,
	},
};

static int msm_flash_lm3646_platform_probe(struct platform_device *pdev)
{
	const struct of_device_id *match;
	int rc;

	CDBG("%s:", __func__);
	match = of_match_device(lm3646_trigger_dt_match, &pdev->dev);
	if (!match)
		return -EFAULT;
	rc = msm_led_lm3646_get_dt_data(pdev->dev.of_node, &fctrl);

	if (rc)
		return -EFAULT;
	return msm_flash_probe(pdev, match->data);
}

static struct platform_driver lm3646_platform_driver = {
	.probe = msm_flash_lm3646_platform_probe,
	.driver = {
		.name = FLASH_NAME,
		.owner = THIS_MODULE,
		.of_match_table = lm3646_trigger_dt_match,
	},
};
#ifdef TEST_TORCH
void my_flash(void)
{
	int rc;

	soc_kobj = kobject_create_and_add("my_flash", NULL);
	rc = sysfs_create_group(soc_kobj, &flash_attr_group);
}
#endif
static int __init msm_flash_lm3646_init_module(void)
{
	int32_t rc = 0;

	CDBG("%s:", __func__);
	rc = platform_driver_register(&lm3646_platform_driver);
	CDBG("%s: rc = %d", __func__, rc);
	if (!rc) {
		CDBG("lijianjun: flash %s,%d\n", __func__, __LINE__);
		#ifdef TEST_TORCH
		my_flash();
		#endif
		return rc;
	}
	CDBG("%s:%d rc %d\n", __func__, __LINE__, rc);
	pr_debug("%s:%d rc %d\n", __func__, __LINE__, rc);
	return i2c_add_driver(&lm3646_i2c_driver);
}

static void __exit msm_flash_lm3646_exit_module(void)
{
	if (fctrl.pdev)
		platform_driver_unregister(&lm3646_platform_driver);
	else
		i2c_del_driver(&lm3646_i2c_driver);
}

static int msm_flash_lm3646_led_init(struct msm_led_flash_ctrl_t *fctrl)
{
	int rc = 0, ret = 0;
	int m = 1000;
	uint16_t flag_reg = 0x0;
	struct msm_camera_sensor_board_info *flashdata = NULL;
	struct msm_camera_power_ctrl_t *power_info = NULL;

	CDBG("%s:%d called\n", __func__, __LINE__);
	flashdata = fctrl->flashdata;
	power_info = &flashdata->power_info;

	m = msm_camera_config_single_vreg(&fctrl->pdev->dev,
		&fctrl->cam_vreg, (struct regulator **)&lm3646_flash_power_setting->data[0], 1);

	/* printk("%s:%d %d\n",__func__,__LINE__,m); */
	/*msleep(3000);*/
	if (power_info->gpio_conf->cam_gpiomux_conf_tbl != NULL) {
		pr_err("%s:%d mux install\n", __func__, __LINE__);
		/*
		///////duyuerong delete it because add #include <mach/gpiomux.h> handle ---error!
		msm_gpiomux_install(
			(struct msm_gpiomux_config *)
			power_info->gpio_conf->cam_gpiomux_conf_tbl,
			power_info->gpio_conf->cam_gpiomux_conf_tbl_size);
		*/
	}

	CDBG("%s: fctrl->flash_device_type = %d\n", __func__, fctrl->flash_device_type);

	/* CCI Init */
	if (fctrl->flash_device_type == MSM_CAMERA_PLATFORM_DEVICE) {
		rc = fctrl->flash_i2c_client->i2c_func_tbl->i2c_util(
			fctrl->flash_i2c_client, MSM_CCI_INIT);
		CDBG("%s: call cci_init rc = %d\n", __func__, rc);
		if (rc < 0)
			pr_err("cci_init failed\n");
	}

	CDBG("%s: call msm_flash_my cci_init rc = %d\n", __func__, rc);

	rc = msm_camera_request_gpio_table(
		power_info->gpio_conf->cam_gpio_req_tbl,
		power_info->gpio_conf->cam_gpio_req_tbl_size, 1);
	if (rc < 0) {
		pr_err("%s: request gpio failed\n", __func__);
		return rc;
	}
	msleep(20);
	CDBG("%s: msleep20\n", __func__);
	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_EN],
		GPIO_OUT_LOW);

	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_EN],
		GPIO_OUT_HIGH);

	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_NOW],
		GPIO_OUT_LOW);
	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_NOW],
		GPIO_OUT_HIGH);

	fctrl->flash_i2c_client->addr_type =  MSM_CAMERA_I2C_BYTE_ADDR;
	ret = fctrl->flash_i2c_client->i2c_func_tbl->i2c_read(fctrl->flash_i2c_client,
			0x01, &flag_reg, MSM_CAMERA_I2C_BYTE_DATA);
	CDBG("%s: callmsm_flash_my	ret =%d\n", __func__, ret);

	if (ret < 0)
		 pr_err("%s read flag register failed, rc = %d\n", __func__, rc);

	pr_err("%s read flag register = %d\n", __func__, flag_reg);
	pr_err("sid=0x%x", fctrl->flash_i2c_client->cci_client->sid);
	/* gpio_set_value_cansleep(55,GPIO_OUT_LOW);*/
	CDBG("%s: callmsm_flash_my\n", __func__);
	/*	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_EN],
		GPIO_OUT_LOW); */
	CDBG("%s: callmsm_flash_my	end\n", __func__);
	return rc;
}

static int msm_flash_lm3646_led_release(struct msm_led_flash_ctrl_t *fctrl)
{
	int rc = 0;
	struct msm_camera_sensor_board_info *flashdata = NULL;
	struct msm_camera_power_ctrl_t *power_info = NULL;

	flashdata = fctrl->flashdata;
	power_info = &flashdata->power_info;
	CDBG(" %s:%d called\n", __func__, __LINE__);
	if (!fctrl) {
		pr_err("%s:%d fctrl NULL\n", __func__, __LINE__);
		return -EINVAL;
	}

	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_EN],
		GPIO_OUT_LOW);

	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_NOW],
		GPIO_OUT_LOW);

		gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_RESET],
		GPIO_OUT_LOW);

	rc = msm_camera_request_gpio_table(
		power_info->gpio_conf->cam_gpio_req_tbl,
		power_info->gpio_conf->cam_gpio_req_tbl_size, 0);
	if (rc < 0) {
		pr_err("%s: request gpio failed\n", __func__);
		return rc;
	}

	/* CCI deInit */
	if (fctrl->flash_device_type == MSM_CAMERA_PLATFORM_DEVICE) {
		rc = fctrl->flash_i2c_client->i2c_func_tbl->i2c_util(
			fctrl->flash_i2c_client, MSM_CCI_RELEASE);
		if (rc < 0)
			pr_err("cci_deinit failed\n");
	}
	CDBG(" %s:%d called\n", __func__, __LINE__);

	return 0;
}

static int msm_flash_lm3646_led_off(struct msm_led_flash_ctrl_t *fctrl)
{
	int rc = 0;
	struct msm_camera_sensor_board_info *flashdata = NULL;
	struct msm_camera_power_ctrl_t *power_info = NULL;

	flashdata = fctrl->flashdata;
	power_info = &flashdata->power_info;
	CDBG(" %s:%d called\n", __func__, __LINE__);
	if (!fctrl) {
		pr_err("%s:%d fctrl NULL\n", __func__, __LINE__);
		return -EINVAL;
	}
		/* CCI Init */
	if (fctrl->flash_device_type == MSM_CAMERA_PLATFORM_DEVICE) {
		rc = fctrl->flash_i2c_client->i2c_func_tbl->i2c_util(
			fctrl->flash_i2c_client, MSM_CCI_INIT);
		if (rc < 0)
			pr_err("cci_init failed\n");
	}

	if (fctrl->flash_i2c_client && fctrl->reg_setting) {
		rc = fctrl->flash_i2c_client->i2c_func_tbl->i2c_write_table(
			fctrl->flash_i2c_client,
			fctrl->reg_setting->off_setting);
		if (rc < 0)
			pr_err("%s:%d failed\n", __func__, __LINE__);
	}

	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_EN],
		GPIO_OUT_LOW);

	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_NOW],
		GPIO_OUT_LOW);

			gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_RESET],
		GPIO_OUT_LOW);
	if (fctrl->flash_device_type == MSM_CAMERA_PLATFORM_DEVICE) {
		rc = fctrl->flash_i2c_client->i2c_func_tbl->i2c_util(
			fctrl->flash_i2c_client, MSM_CCI_RELEASE);
		if (rc < 0)
			pr_err("cci_deinit failed\n");
	}

	return rc;
}


/*lijianjun modify start*/
static struct msm_camera_i2c_reg_array lm3646_config_low_array[] = {
	{0x01,  0xE2},
	 {0x05,  0x7f},
	 {0x07,  0x3f},
};
static struct msm_camera_i2c_reg_setting lm3646_config_low_setting = {
	.reg_setting = lm3646_config_low_array,
	.size = ARRAY_SIZE(lm3646_config_low_array),
	.addr_type = MSM_CAMERA_I2C_BYTE_ADDR,
	.data_type = MSM_CAMERA_I2C_BYTE_DATA,
	.delay = 0,
};
static void lm3646_buildConfigLowSetting(struct msm_flash_cfg_data_t *flash_data)
{
	CDBG("%s,flash_data->torch_current[0] =%d\n", __func__, flash_data->torch_current[0]);
	switch (flash_data->torch_current[0]) {
	case 1:
	{
		lm3646_config_low_setting.reg_setting[1].reg_data = 0x1f;/*max:46.48ma*/
		lm3646_config_low_setting.reg_setting[2].reg_data = 0x0f;
		/*led1:23.24ma  ((23.24-2.53)/1.46) +1 = 15.18*/
	} break;
	case 2:
	{
		lm3646_config_low_setting.reg_setting[1].reg_data = 0x2f;/*max:69.91ma*/
		lm3646_config_low_setting.reg_setting[2].reg_data = 0x17;
		/*led1:34.955ma ((34.955-2.53)/1.46) +1 = 23.209*/
	} break;
	case 3:
	{
		lm3646_config_low_setting.reg_setting[1].reg_data = 0x3f;/*max:93.35ma*/
		lm3646_config_low_setting.reg_setting[2].reg_data = 0x1f;
		/*led1:46.675ma ((46.675-2.53)/1.46) +1 = 31.236*/
	} break;
	case 4:
	{
		lm3646_config_low_setting.reg_setting[1].reg_data = 0x4f;/*max:116.79ma*/
		lm3646_config_low_setting.reg_setting[2].reg_data = 0x27;
		/*led1:58.395ma ((58.395-2.53)/1.46) +1 = 39.236*/
	} break;
	case 5:
	{
		lm3646_config_low_setting.reg_setting[1].reg_data = 0x5f;/*max:140.23ma*/
		lm3646_config_low_setting.reg_setting[2].reg_data = 0x2f;
		/*led1:70.115ma ((70.115-2.53)/1.46) +1 = 47.291*/
	} break;
	case 6:
	{
		lm3646_config_low_setting.reg_setting[1].reg_data = 0x6f;/*max:163.66ma*/
		lm3646_config_low_setting.reg_setting[2].reg_data = 0x37;
		/*led1:81.83ma ((81.83-2.53)/1.46) +1 = 55.315*/
	} break;
	case 7:
	{
		lm3646_config_low_setting.reg_setting[1].reg_data = 0x7f;/*max:187.10ma*/
		lm3646_config_low_setting.reg_setting[2].reg_data = 0x3f;
		/*led1:93.55ma ((34.955-2.53)/1.46) +1 = 63.342*/
	} break;
	default:
	{
		lm3646_config_low_setting.reg_setting[1].reg_data = lm3646_low_array[1].reg_data;
		lm3646_config_low_setting.reg_setting[2].reg_data = lm3646_low_array[2].reg_data;
	} break;
	}
	CDBG(" lm3646_buildConfigLowSetting,torch0:0x%x,torch1 = 0x%x\n",
		lm3646_config_low_setting.reg_setting[1].reg_data,
		lm3646_config_low_setting.reg_setting[2].reg_data);
}
/*lijianjun modify end*/

static int msm_flash_lm3646_led_low(struct msm_led_flash_ctrl_t *fctrl, struct msm_flash_cfg_data_t *flash_data)
{
	int rc = 0;
	struct msm_camera_sensor_board_info *flashdata = NULL;
	struct msm_camera_power_ctrl_t *power_info = NULL;

	CDBG(" %s:%d called zx!\n", __func__, __LINE__);

	flashdata = fctrl->flashdata;
	power_info = &flashdata->power_info;

	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_EN],
		GPIO_OUT_HIGH);

	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_NOW],
		GPIO_OUT_LOW);
		gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_RESET],
		GPIO_OUT_HIGH);
	/*ljianjun  modify start*/
	CDBG(" %s:%d called zx!\n", __func__, __LINE__);
	if (fctrl->flash_i2c_client && fctrl->reg_setting) {
		if (flash_data != NULL) {
			CDBG("%s,flash_data->torch_current[0] =%d\n", __func__, flash_data->torch_current[0]);
			lm3646_buildConfigLowSetting(flash_data);
			rc = fctrl->flash_i2c_client->i2c_func_tbl->i2c_write_table(
				fctrl->flash_i2c_client,
				&(lm3646_config_low_setting));
		} else {
			rc = fctrl->flash_i2c_client->i2c_func_tbl->i2c_write_table(
				fctrl->flash_i2c_client,
				fctrl->reg_setting->low_setting);
		}
		if (rc < 0) {
			pr_err("%s:%d failed\n", __func__, __LINE__);
		}
	}
	/*lijianjun modify end*/


	/*
	if (fctrl->flash_i2c_client && fctrl->reg_setting) {
		rc = fctrl->flash_i2c_client->i2c_func_tbl->i2c_write_table(
			fctrl->flash_i2c_client,
			fctrl->reg_setting->low_setting);
		if (rc < 0)
			pr_err("%s:%d failed\n", __func__, __LINE__);
	}*/

	return rc;
}

static int msm_flash_lm3646_led_high(struct msm_led_flash_ctrl_t *fctrl)
{
	int rc = 0;
	struct msm_camera_sensor_board_info *flashdata = NULL;
	struct msm_camera_power_ctrl_t *power_info = NULL;

	CDBG(" %s:%d called\n", __func__, __LINE__);

	flashdata = fctrl->flashdata;
	power_info = &flashdata->power_info;

	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_EN],
		GPIO_OUT_HIGH);

	gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_NOW],
		GPIO_OUT_HIGH);
		gpio_set_value_cansleep(
		power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_RESET],
		GPIO_OUT_LOW);
		pr_err("HWEN =%d", power_info->gpio_conf->gpio_num_info->
		gpio_num[SENSOR_GPIO_FL_RESET]);

	if (fctrl->flash_i2c_client && fctrl->reg_setting) {
		rc = fctrl->flash_i2c_client->i2c_func_tbl->i2c_write_table(
			fctrl->flash_i2c_client,
			fctrl->reg_setting->high_setting);

		if (rc < 0)
			pr_err("%s:%d failed\n", __func__, __LINE__);
	}

	return rc;
}


static struct msm_camera_i2c_client lm3646_i2c_client = {
	.addr_type = MSM_CAMERA_I2C_BYTE_ADDR,
};

static struct msm_camera_i2c_reg_setting lm3646_init_setting = {
	.reg_setting = lm3646_init_array,
	.size = ARRAY_SIZE(lm3646_init_array),
	.addr_type = MSM_CAMERA_I2C_BYTE_ADDR,
	.data_type = MSM_CAMERA_I2C_BYTE_DATA,
	.delay = 0,
};

static struct msm_camera_i2c_reg_setting lm3646_off_setting = {
	.reg_setting = lm3646_off_array,
	.size = ARRAY_SIZE(lm3646_off_array),
	.addr_type = MSM_CAMERA_I2C_BYTE_ADDR,
	.data_type = MSM_CAMERA_I2C_BYTE_DATA,
	.delay = 0,
};


static struct msm_camera_i2c_reg_setting lm3646_release_setting = {
	.reg_setting = lm3646_release_array,
	.size = ARRAY_SIZE(lm3646_release_array),
	.addr_type = MSM_CAMERA_I2C_BYTE_ADDR,
	.data_type = MSM_CAMERA_I2C_BYTE_DATA,
	.delay = 0,
};

static struct msm_camera_i2c_reg_setting lm3646_low_setting = {
	.reg_setting = lm3646_low_array,
	.size = ARRAY_SIZE(lm3646_low_array),
	.addr_type = MSM_CAMERA_I2C_BYTE_ADDR,
	.data_type = MSM_CAMERA_I2C_BYTE_DATA,
	.delay = 0,
};

static struct msm_camera_i2c_reg_setting lm3646_high_setting = {
	.reg_setting = lm3646_high_array,
	.size = ARRAY_SIZE(lm3646_high_array),
	.addr_type = MSM_CAMERA_I2C_BYTE_ADDR,
	.data_type = MSM_CAMERA_I2C_BYTE_DATA,
	.delay = 0,
};


static struct msm_led_flash_reg_t lm3646_regs = {
	.init_setting = &lm3646_init_setting,
	.off_setting = &lm3646_off_setting,
	.low_setting = &lm3646_low_setting,
	.high_setting = &lm3646_high_setting,
	.release_setting = &lm3646_release_setting,
};

static struct msm_flash_fn_t lm3646_func_tbl = {
	.flash_get_subdev_id = msm_led_i2c_trigger_get_subdev_id,
	.flash_led_config = msm_led_i2c_trigger_config,
	.flash_led_init = msm_flash_lm3646_led_init,
	.flash_led_release = msm_flash_lm3646_led_release,
	.flash_led_off = msm_flash_lm3646_led_off,
	.flash_led_low = msm_flash_lm3646_led_low,
	.flash_led_high = msm_flash_lm3646_led_high,
	/*.flash_led_torch= msm_flash_lm3646_led_torch,*/
};

static struct msm_led_flash_ctrl_t fctrl = {
	.flash_i2c_client = &lm3646_i2c_client,
	.reg_setting = &lm3646_regs,
	.func_tbl = &lm3646_func_tbl,
};


/*subsys_initcall(msm_flash_i2c_add_driver);*/
module_init(msm_flash_lm3646_init_module);
module_exit(msm_flash_lm3646_exit_module);
MODULE_DESCRIPTION("lm3646 FLASH");
MODULE_LICENSE("GPL v2");
