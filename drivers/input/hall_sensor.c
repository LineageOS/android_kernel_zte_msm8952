/*
 *
 * Copyright (c) 2014-2015, The Linux Foundation. All rights reserved.
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

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/input.h>
#include <linux/irq.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/pm.h>
#include <linux/module.h>
#include <linux/regulator/consumer.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>

#define	LID_DEV_NAME	"hall_sensor"
#define HALL_INPUT	"/dev/input/hall_dev"
extern int gloved_finger_hall_status(bool flag); /* add by tp for gloved mode */

struct hall_data {
	int gpio;	/* device use gpio number */
	int irq;	/* device request irq number */
	int active_low;	/* gpio active high or low for valid value */
	bool wakeup;	/* device can wakeup system or not */
	struct input_dev *hall_dev;
	struct regulator *vddio;
	u32 min_uv;	/* device allow minimum voltage */
	u32 max_uv;	/* device allow max voltage */
};

struct hall_data *g_hall_data;
static irqreturn_t hall_interrupt_handler(int irq, void *dev)
{
	int value;
	struct hall_data *data = dev;

	value = (gpio_get_value_cansleep(data->gpio) ? 1 : 0) ^
		data->active_low;
	if (value) {
		input_report_switch(data->hall_dev, SW_LID, 0);
		gloved_finger_hall_status(false);
		dev_dbg(&data->hall_dev->dev, "far\n");
	} else {
		input_report_switch(data->hall_dev, SW_LID, 1);
		gloved_finger_hall_status(true);
		dev_dbg(&data->hall_dev->dev, "near\n");
	}
	input_sync(data->hall_dev);

	return IRQ_HANDLED;
}

static int hall_input_init(struct platform_device *pdev,
		struct hall_data *data)
{
	int err = -1;

	data->hall_dev = devm_input_allocate_device(&pdev->dev);
	if (!data->hall_dev) {
		dev_err(&data->hall_dev->dev,
				"input device allocation failed\n");
		return -EINVAL;
	}
	data->hall_dev->name = LID_DEV_NAME;
	data->hall_dev->phys = HALL_INPUT;
	__set_bit(EV_SW, data->hall_dev->evbit);
	__set_bit(SW_LID, data->hall_dev->swbit);

	err = input_register_device(data->hall_dev);
	if (err < 0) {
		dev_err(&data->hall_dev->dev,
				"unable to register input device %s\n",
				LID_DEV_NAME);
		return err;
	}

	return 0;
}

static int hall_config_regulator(struct platform_device *dev, bool on)
{
	struct hall_data *data = dev_get_drvdata(&dev->dev);
	int rc = 0;

	if (on) {
		data->vddio = devm_regulator_get(&dev->dev, "vddio");
		if (IS_ERR(data->vddio)) {
			rc = PTR_ERR(data->vddio);
			dev_err(&dev->dev, "Regulator vddio get failed rc=%d\n",
					rc);
			data->vddio = NULL;
			return rc;
		}

		if (regulator_count_voltages(data->vddio) > 0) {
			rc = regulator_set_voltage(
					data->vddio,
					data->min_uv,
					data->max_uv);
			if (rc) {
				dev_err(&dev->dev, "Regulator vddio Set voltage failed rc=%d\n",
						rc);
				goto deinit_vregs;
			}
		}
		return rc;
	} else {
		goto deinit_vregs;
	}

deinit_vregs:
	if (regulator_count_voltages(data->vddio) > 0)
		regulator_set_voltage(data->vddio, 0, data->max_uv);

	return rc;
}

static int hall_set_regulator(struct platform_device *dev, bool on)
{
	struct hall_data *data = dev_get_drvdata(&dev->dev);
	int rc = 0;

	if (on) {
		if (!IS_ERR_OR_NULL(data->vddio)) {
			rc = regulator_enable(data->vddio);
			if (rc) {
				dev_err(&dev->dev, "Enable regulator vddio failed rc=%d\n",
					rc);
				goto disable_regulator;
			}
		}
		return rc;
	} else {
		if (!IS_ERR_OR_NULL(data->vddio)) {
			rc = regulator_disable(data->vddio);
			if (rc)
				dev_err(&dev->dev, "Disable regulator vddio failed rc=%d\n",
					rc);
		}
		return 0;
	}

disable_regulator:
	if (!IS_ERR_OR_NULL(data->vddio))
		regulator_disable(data->vddio);
	return rc;
}

#ifdef CONFIG_OF
static int hall_parse_dt(struct device *dev, struct hall_data *data)
{
	unsigned int tmp;
	u32 tempval;
	int rc;
	struct device_node *np = dev->of_node;

	data->gpio = of_get_named_gpio_flags(dev->of_node,
			"linux,gpio-int", 0, &tmp);
	if (!gpio_is_valid(data->gpio)) {
		dev_err(dev, "hall gpio is not valid\n");
		return -EINVAL;
	}
	data->active_low = tmp & OF_GPIO_ACTIVE_LOW ? 0 : 1;

	data->wakeup = of_property_read_bool(np, "linux,wakeup");

	rc = of_property_read_u32(np, "linux,max-uv", &tempval);
	if (rc) {
		dev_err(dev, "unable to read max-uv\n");
		return -EINVAL;
	}
	data->max_uv = tempval;

	rc = of_property_read_u32(np, "linux,min-uv", &tempval);
	if (rc) {
		dev_err(dev, "unable to read min-uv\n");
		return -EINVAL;
	}
	data->min_uv = tempval;

	return 0;
}
#else
static int hall_parse_dt(struct device *dev, struct hall_data *data)
{
	return -EINVAL;
}
#endif

static int hall_status_proc_show(struct seq_file *m, void *v)
{
	int value;

	value = (gpio_get_value_cansleep(g_hall_data->gpio) ? 1 : 0) ^
		g_hall_data->active_low;
	if (value)
		seq_puts(m, "0\n");
	else
		seq_puts(m, "1\n");

	return 0;
}

static int hall_status_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hall_status_proc_show, NULL);
}

static const struct file_operations hall_status_proc_fops = {
	.open		= hall_status_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int hall_status_proc_init(void)
{
	struct proc_dir_entry *res;

	res = proc_create("hall_status",  0, NULL,
			  &hall_status_proc_fops);
	if (!res) {
		dev_err(&g_hall_data->hall_dev->dev, "failed to create hall_status\n");
		return -ENOMEM;
	}

	dev_dbg(&g_hall_data->hall_dev->dev, "created hall_status\n");
	return 0;
}

static ssize_t hall_device_status_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct hall_data *data = dev_get_drvdata(dev);
	int value;

	value = (gpio_get_value_cansleep(data->gpio) ? 1 : 0) ^
		data->active_low;

	return snprintf(buf, sizeof(int), "%d\n", value);
}

static struct device_attribute hall_attrs[] = {
	__ATTR(hall_status, 0444, hall_device_status_show, NULL),
};

static int add_sysfs_interfaces(struct device *dev,
	struct device_attribute *a, int size)
{
	int i;

	for (i = 0; i < size; i++)
		if (device_create_file(dev, a + i))
			goto undo;

	return 0;

undo:
	for (; i >= 0 ; i--)
		device_remove_file(dev, a + i);
	dev_dbg(dev, "%s: failed to create sysfs interface\n", __func__);

	return -ENODEV;
}
static int hall_driver_probe(struct platform_device *dev)
{
	struct hall_data *data;
	int err = 0;
	int irq_flags;

	dev_dbg(&dev->dev, "hall_driver probe\n");
	data = devm_kzalloc(&dev->dev, sizeof(struct hall_data), GFP_KERNEL);
	if (data == NULL) {
		err = -ENOMEM;
		dev_err(&dev->dev,
				"failed to allocate memory %d\n", err);
		goto exit;
	}

	g_hall_data = data;
	dev_set_drvdata(&dev->dev, data);
	if (dev->dev.of_node) {
		err = hall_parse_dt(&dev->dev, data);
		if (err < 0) {
			dev_err(&dev->dev, "Failed to parse device tree\n");
			goto exit;
		}
	} else if (dev->dev.platform_data != NULL) {
		memcpy(data, dev->dev.platform_data, sizeof(*data));
	} else {
		dev_err(&dev->dev, "No valid platform data.\n");
		err = -ENODEV;
		goto exit;
	}

	err = hall_input_init(dev, data);
	if (err < 0) {
		dev_err(&dev->dev, "input init failed\n");
		goto exit;
	}

	if (!gpio_is_valid(data->gpio)) {
		dev_err(&dev->dev, "gpio is not valid\n");
		err = -EINVAL;
		goto exit;
	}

	irq_flags = IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING
		| IRQF_ONESHOT;
	err = gpio_request_one(data->gpio, GPIOF_DIR_IN, "hall_sensor_irq");
	if (err) {
		dev_err(&dev->dev, "unable to request gpio %d\n", data->gpio);
		goto exit;
	}

	data->irq = gpio_to_irq(data->gpio);
	err = devm_request_threaded_irq(&dev->dev, data->irq, NULL,
			hall_interrupt_handler,
			irq_flags, "hall_sensor", data);
	if (err < 0) {
		dev_err(&dev->dev, "request irq failed : %d\n", data->irq);
		goto free_gpio;
	}

	device_init_wakeup(&dev->dev, data->wakeup);
	enable_irq_wake(data->irq);

	err = hall_config_regulator(dev, true);
	if (err < 0) {
		dev_err(&dev->dev, "Configure power failed: %d\n", err);
		goto free_irq;
	}

	err = hall_set_regulator(dev, true);
	if (err < 0) {
		dev_err(&dev->dev, "power on failed: %d\n", err);
		goto err_regulator_init;
	}

	err = add_sysfs_interfaces(&dev->dev, hall_attrs, ARRAY_SIZE(hall_attrs));
	if (err < 0) {
		dev_err(&dev->dev, "sysfs interface add failed: %d\n", err);
		goto exit;
	}

	hall_status_proc_init();
	return 0;

err_regulator_init:
	hall_config_regulator(dev, false);
free_irq:
	disable_irq_wake(data->irq);
	device_init_wakeup(&dev->dev, 0);
free_gpio:
	gpio_free(data->gpio);
exit:
	return err;
}

static int hall_driver_remove(struct platform_device *dev)
{
	struct hall_data *data = dev_get_drvdata(&dev->dev);

	disable_irq_wake(data->irq);
	device_init_wakeup(&dev->dev, 0);
	if (data->gpio)
		gpio_free(data->gpio);
	hall_set_regulator(dev, false);
	hall_config_regulator(dev, false);

	return 0;
}

static struct platform_device_id hall_id[] = {
	{LID_DEV_NAME, 0 },
	{ },
};


#ifdef CONFIG_OF
static struct of_device_id hall_match_table[] = {
	{.compatible = "hall-switch", },
	{ },
};
#endif

static struct platform_driver hall_driver = {
	.driver = {
		.name = LID_DEV_NAME,
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(hall_match_table),
	},
	.probe = hall_driver_probe,
	.remove = hall_driver_remove,
	.id_table = hall_id,
};

static int __init hall_init(void)
{
	return platform_driver_register(&hall_driver);
}

static void __exit hall_exit(void)
{
	platform_driver_unregister(&hall_driver);
}

module_init(hall_init);
module_exit(hall_exit);
MODULE_DESCRIPTION("Hall sensor driver");
MODULE_LICENSE("GPL v2");
