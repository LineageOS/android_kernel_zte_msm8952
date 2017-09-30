/*\file sx9500.c
 * \brief	SX9500 Driver
 *
 * Driver for the SX9500
 * Copyright (c) 2016 ZTE Corp
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */
/*#define DEBUG*/
#define DRIVER_NAME "sx9500"

#define MAX_WRITE_ARRAY_SIZE 32
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/input.h>

#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/regulator/consumer.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>

#include "sx9500.h"
#include <linux/fb.h>
#include <soc/qcom/socinfo.h>/*for pv-version check */

#define IDLE 0
#define ACTIVE 1

#define SX9500_TAG					"==ZTE-SX9500=="
#define SX9500_DBG(fmt, args...)	printk(SX9500_TAG fmt, ##args)
#define SX9500_DBG2(fmt, args...)	/*printk(SX9500_TAG	fmt, ##args) */

#ifdef CONFIG_BOARD_JASMINE
static struct smtc_reg_data sx9500_i2c_reg_setup[] = {
	{
	.reg = SX9500_IRQ_ENABLE_REG,
	/*.val = 0xFF,*/
	/*.val = 0x60,*/
	/*.val = 0x00,*/
	.val = 0x60
	},
	{
		.reg = SX9500_CPS_CTRL0_REG,
		/*.val = 0x2F,*/
		.val = 0x41,
	},
	{
	.reg = SX9500_CPS_CTRL1_REG,
	.val = 0x03,
	},
	{
	.reg = SX9500_CPS_CTRL2_REG,
	.val = 0x6F,
	},
	{
	.reg = SX9500_CPS_CTRL3_REG,
	.val = 0x01,
	},
	{
	.reg = SX9500_CPS_CTRL4_REG,
	/*.val = 0x20,
	.val = 0x30,*/
	.val = 0xE0,
	},
	{
	.reg = SX9500_CPS_CTRL5_REG,
	.val = 0x0F,
	},
	{
	.reg = SX9500_CPS_CTRL6_REG,
	/*.val = 0x04,*/
	.val = 0x03,
	},
	{
	.reg = SX9500_CPS_CTRL7_REG,
	.val = 0x00,
	},
	{
	.reg = SX9500_CPS_CTRL8_REG,
	.val = 0x00,
	},
};
#else
static struct smtc_reg_data sx9500_i2c_reg_setup[] = {
	{
	.reg = SX9500_IRQ_ENABLE_REG,
	/*.val = 0xFF,*/
	/*.val = 0x60,*/
	/*.val = 0x00,*/
	.val = 0x60
	},
	{
	.reg = SX9500_CPS_CTRL0_REG,
	/*.val = 0x2F,*/
	.val = 0x21,
	},
	{
	.reg = SX9500_CPS_CTRL1_REG,
	.val = 0x03,
	},
	{
	.reg = SX9500_CPS_CTRL2_REG,
	.val = 0x77,
	},
	{
	.reg = SX9500_CPS_CTRL3_REG,
	.val = 0x01,
	},
	{
	.reg = SX9500_CPS_CTRL4_REG,
	/*.val = 0x20,
	.val = 0x30,*/
	.val = 0xE0,
	},
	{
	.reg = SX9500_CPS_CTRL5_REG,
	/*.val = 0x16,*/
	.val = 0x0F,
	},
	{
	.reg = SX9500_CPS_CTRL6_REG,
	/*.val = 0x06,
	.val = 0x05,
	.val = 0x08,*/
	.val = 0x0F,
	},
	{
	.reg = SX9500_CPS_CTRL7_REG,
	.val = 0x00,
	},
	{
	.reg = SX9500_CPS_CTRL8_REG,
	.val = 0x00,
	},
};
#endif

static struct _buttonInfo psmtcButtons[] = {
	{
	/*.keycode = KEY_0,*/
	.keycode = KEY_F20,
	.mask = SX9500_TCHCMPSTAT_TCHSTAT0_FLAG,
	},
	{
	/*.keycode = KEY_1,*/
	.keycode = KEY_F21,
	.mask = SX9500_TCHCMPSTAT_TCHSTAT1_FLAG,
	},
	{
	/*.keycode = KEY_2,*/
	.keycode = KEY_F22,
	.mask = SX9500_TCHCMPSTAT_TCHSTAT2_FLAG,
	},
	{
	/*.keycode = KEY_3,*/
	.keycode = KEY_F23,
	.mask = SX9500_TCHCMPSTAT_TCHSTAT3_FLAG,
	},
};

#define MAX_NUM_STATUS_BITS 8

typedef struct sx9500_chip sx9500_chip_t, *psx9500_chip_t;
struct sx9500_chip {
	void *bus; /* either i2c_client or spi_client */

	struct device *pdev; /* common device struction for linux */

	void *pDevice; /* device specific struct pointer */

#if defined(USE_THREADED_IRQ)
	struct mutex mutex;
#else
	spinlock_t			lock; /* Spin Lock used for nirq worker function */
#endif
	int irq; /* irq number used */

	/* whether irq should be ignored.. cases if enable/disable irq is not used
	 * or does not work properly */
	char irq_disabled;

	/*u8 useIrqTimer; // older models need irq timer for pen up cases */

	int irqTimeout; /* msecs only set if useIrqTimer is true */

	/* struct workqueue_struct	*ts_workq;	*/	/* if want to use non default */
	struct delayed_work dworker; /* work struct for worker function */
	struct delayed_work resume_worker; /* work struct for worker function */

	struct input_dev *pinput;
	struct _buttonInfo *buttons;
	int buttonSize;

	struct pinctrl			*pinctrl;
	struct pinctrl_state		*sx9500_active;
	struct pinctrl_state		*sx9500_sleep;
	struct regulator			 *sx9500_vdd;
	struct regulator			 *sx9500_svdd;
	int irq_gpio;
};

#define SSD1306B_ACTIVE "sx9500_active"
#define SSD1306B_SLEEP "sx9500_sleep"

psx9500_chip_t g_sx9500_chip = 0;

void sx9500_touchProcess(psx9500_chip_t chip);
int initialize(psx9500_chip_t chip);
int read_regStat(psx9500_chip_t chip);
int manual_offset_calibration(psx9500_chip_t chip);

unsigned char g_enable_log = 0;

static int write_register(psx9500_chip_t chip, u8 address, u8 value)
{
	struct i2c_client *i2c = 0;
	char buffer[2];
	int returnValue = 0;

	buffer[0] = address;
	buffer[1] = value;
	returnValue = -ENOMEM;
	if (chip && chip->bus) {
	i2c = chip->bus;

	returnValue = i2c_master_send(i2c, buffer, 2);
	dev_dbg(&i2c->dev, "write_register Address: 0x%x Value: 0x%x Return: %d\n",
			address, value, returnValue);
	}

	return returnValue;
}

static int read_register(psx9500_chip_t chip, u8 address, u8 *value)
{
	struct i2c_client *i2c = 0;
	s32 returnValue = 0;

	if (chip && value && chip->bus) {
	i2c = chip->bus;
	returnValue = i2c_smbus_read_byte_data(i2c, address);
		dev_dbg(&i2c->dev, "read_register Address: 0x%x Return: 0x%x\n", address, returnValue);
	if (returnValue >= 0) {
		*value = returnValue;
		return 0;
	} else {
		return returnValue;
	}
	}
	return -ENOMEM;
}

#if 0
static int write_registerEx(psx9500_chip_t chip, unsigned char reg,
				unsigned char *data, int size)
{
	struct i2c_client *i2c = 0;
	u8 tx[MAX_WRITE_ARRAY_SIZE];
	int ret = 0;

	i2c = chip->bus£»
	if (chip && i2c && data && (size <= MAX_WRITE_ARRAY_SIZE)) {
	dev_dbg(chip->pdev, "inside write_registerEx()\n");
	tx[0] = reg;
	dev_dbg(chip->pdev, "going to call i2c_master_send(0x%p, 0x%x ",
			(void *)i2c, tx[0]);
	for (ret = 0; ret < size; ret++) {
		tx[ret+1] = data[ret];
		dev_dbg(chip->pdev, "0x%x, ", tx[ret+1]);
	}
	dev_dbg(chip->pdev, "\n");

	ret = i2c_master_send(i2c, tx, size+1);
		if (ret < 0)
		dev_err(chip->pdev, "I2C write error\n");
	}
	dev_dbg(chip->pdev, "leaving write_registerEx()\n");


	return ret;
}

static int read_registerEx(psx9500_chip_t chip, unsigned char reg,
				unsigned char *data, int size)
{
	struct i2c_client *i2c = 0;
	int ret = 0;
	u8 tx[] = {
		reg
	};
	i2c = chip->bus£»
	if (chip && i2c && data && (size <= MAX_WRITE_ARRAY_SIZE)) {
	dev_dbg(chip->pdev, "inside read_registerEx()\n");
	dev_dbg(chip->pdev, "going to call i2c_master_send(0x%p, 0x%p, 1) Reg: 0x%x\n",
		 (void *)i2c, (void *)tx, tx[0]);
	ret = i2c_master_send(i2c, tx, 1);
	if (ret >= 0) {
		dev_dbg(chip->pdev, "going to call i2c_master_recv(0x%p, 0x%p, %x)\n",
				(void *)i2c, (void *)data, size);
		ret = i2c_master_recv(i2c, data, size);
	}
	}
	if (unlikely(ret < 0))
		dev_err(chip->pdev, "I2C read error\n");
	dev_dbg(chip->pdev, "leaving read_registerEx()\n");
	return ret;
}
#endif

#ifdef USE_THREADED_IRQ
static void sx9500_process_interrupt(psx9500_chip_t chip, u8 nirqlow)
{
	int status = 0;
	int counter = 0;

	if (!chip) {
	pr_err("%s, NULL sx86XX_t\n", __func__);
	return;
	}
	/* since we are not in an interrupt don't need to disable irq. */
	status = read_regStat(chip);
	counter = 0;
	dev_dbg(chip->pdev, "Worker - Refresh Status %d\n", status);
	while (counter < MAX_NUM_STATUS_BITS) { /* counter start from MSB */
		dev_dbg(chip->pdev, "Looping Counter %d\n", counter);
	counter++;
	}

#if 0
	if (unlikely(chip->useIrqTimer && nirqlow)) {
	/* In case we need to send a timer for example on a touchscreen
	 * checking penup, perform this here
	 */
	cancel_delayed_work(&chip->dworker);
	schedule_delayed_work(&chip->dworker, msecs_to_jiffies(chip->irqTimeout));
	dev_info(chip->pdev, "Schedule Irq timer");
	}
#endif
}


static void sx9500_worker_func(struct work_struct *work)
{
	psx9500_chip_t chip = 0;

	if (work) {
	chip = container_of(work, sx9500_chip_t, dworker.work);
	if (!chip) {
		pr_err("sx86XX_worker_func, NULL sx86XX_t\n");
		return;
	}
	sx9500_process_interrupt(chip, 0);
	} else {
	pr_err("%s, NULL work_struct\n", __func__);
	}
}
static irqreturn_t sx9500_interrupt_thread(int irq, void *data)
{
	psx9500_chip_t chip = 0;

	chip = data;
	mutex_lock(&chip->mutex);
	dev_dbg(chip->pdev, "%s\n", __func__);
	sx9500_process_interrupt(chip, 1);
	mutex_unlock(&chip->mutex);
	return IRQ_HANDLED;
}
#else
static void sx9500_schedule_work(psx9500_chip_t chip, unsigned long delay)
{
	unsigned long flags;

	if (chip) {
	 dev_dbg(chip->pdev, "%s\n", __func__);
	 spin_lock_irqsave(&chip->lock, flags);
	 /* Stop any pending penup queues */
	 cancel_delayed_work(&chip->dworker);
	 schedule_delayed_work(&chip->dworker, delay);
	 spin_unlock_irqrestore(&chip->lock, flags);
	} else
	pr_err("%s, NULL psx9500_chip_t\n", __func__);
}

static irqreturn_t sx9500_irq(int irq, void *pvoid)
{
	psx9500_chip_t chip = 0;

	if (pvoid) {
	chip = (psx9500_chip_t)pvoid;
		dev_dbg(chip->pdev, "%s\n", __func__);
		dev_dbg(chip->pdev, "%s - Schedule Work\n", __func__);
		sx9500_schedule_work(chip, 0);
	} else
	pr_err("%s, NULL pvoid\n", __func__);
	return IRQ_HANDLED;
}

static void sx9500_worker_func(struct work_struct *work)
{
	psx9500_chip_t chip = 0;
	int status = 0;

	unsigned char debug_reg[] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x7f};
	int debug_index = 0;
	unsigned char debug_reg_val;
	int debug_size = 0;

	/*u8 nirqLow = 0;
	SX9500_DBG("%s enter\n", __func__);*/
	if (work) {
	chip = container_of(work, sx9500_chip_t, dworker.work);

	if (!chip) {
		pr_err("%s, NULL psx9500_chip_t\n", __func__);
		return;
	}
#if 0
	if (unlikely(chip->useIrqTimer)) {
		nirqLow = 1;
	}
#endif
	/* since we are not in an interrupt don't need to disable irq. */
	status = read_regStat(chip);
	/*dev_info(chip->pdev, "Worker - Refresh Status %d\n", status);*/
	SX9500_DBG("%s Worker - Refresh Status %d\n", __func__, status);

	if (g_enable_log) {
		debug_size = sizeof(debug_reg);
		for (debug_index = 0; debug_index < debug_size; debug_index++) {
			read_register(chip, debug_reg[debug_index], &debug_reg_val);
			pr_err("%s, sx9502 reg 0x%x value = 0x%x\n", __func__, debug_reg[debug_index], debug_reg_val);
		}
	}

	if (BITGET(status, SX9500_TOUCH_BIT) || BITGET(status, SX9500_REASE_BIT))
		sx9500_touchProcess(chip);
#if 0
	if (unlikely(chip->useIrqTimer && nirqLow)) {
	/* Early models and if RATE=0 for newer models require a penup timer */
	/* Queue up the function again for checking on penup */
		sx9500_schedule_work(chip, msecs_to_jiffies(chip->irqTimeout));
	}
#endif
	} else {
	/*pr_err("%s, NULL work_struct\n", __func__);*/
	}
}

static void sx9500_resume_worker_func(struct work_struct *work)
{
	psx9500_chip_t chip = 0;
	struct input_dev *input = NULL;
	u8 touchStatus = 0;

	SX9500_DBG("%s enter\n", __func__);

	if (work) {
	chip = container_of(work, sx9500_chip_t, resume_worker.work);

	if (!chip) {
		pr_err("%s, NULL psx9500_chip_t\n", __func__);
		return;
	}

	input = chip->pinput;

	/*manual_offset_calibration(chip);*/
	read_regStat(chip);
	/*msleep(100);*/
	read_register(chip, SX9500_TCHCMPSTAT_REG, &touchStatus);
	SX9500_DBG("%s Refresh touch Status %d\n", __func__, touchStatus);

	/*manual_offset_calibration(chip);*/
#if 0
	if (touchStatus & 0x10) {
		SX9500_DBG("%s key touch and report\n", __func__);
		input_report_key(input, KEY_F20, 1);
	} else {
		SX9500_DBG("%s key release and report\n", __func__);
		input_report_key(input, KEY_F20, 0);
	}
	input_sync(input);
#endif

	/*enable irq
	enable_irq(chip->irq);
	chip->irq_disabled = 0;*/
	}
}
#endif


int sx9500_init(psx9500_chip_t chip)
{
	int err = 0;

	SX9500_DBG("%s Enter\n", __func__);
	if (chip) {
	if (chip->sx9500_vdd)
		err = regulator_enable(chip->sx9500_vdd);

	if (chip->sx9500_svdd)
		err = regulator_enable(chip->sx9500_svdd);

	if (chip->pinctrl) {
		err = pinctrl_select_state(chip->pinctrl, chip->sx9500_sleep);
		if (err) {
			pr_err("select sx9500_sleep failed with %d\n", err);
			return err;
		}

		msleep(20);

		err = pinctrl_select_state(chip->pinctrl, chip->sx9500_active);
		if (err) {
			pr_err("select sx9500_active failed with %d\n", err);
			return err;
		}
		msleep(20);
	}

#ifdef USE_THREADED_IRQ
	/* initialize worker function */
		INIT_DELAYED_WORK(&chip->dworker, sx9500_worker_func);


	/* initialize mutex */
	mutex_init(&chip->mutex);
	/* initailize interrupt reporting */
	chip->irq_disabled = 0;
		err = request_threaded_irq(chip->irq, NULL, sx9500_interrupt_thread,
								IRQF_TRIGGER_FALLING, chip->pdev->driver->name,
								chip);
#else
	/* initialize spin lock */
	spin_lock_init(&chip->lock);

	/* initialize worker function */
	INIT_DELAYED_WORK(&chip->dworker, sx9500_worker_func);
	INIT_DELAYED_WORK(&chip->resume_worker, sx9500_resume_worker_func);

	/* initailize interrupt reporting */
	chip->irq_disabled = 0;
		err = request_irq(chip->irq, sx9500_irq, IRQF_TRIGGER_FALLING,
					chip->pdev->driver->name, chip);
#endif
		if (err) {
			dev_err(chip->pdev, "irq %d busy?\n", chip->irq);
			return err;
	}
#ifdef USE_THREADED_IRQ
	dev_info(chip->pdev, "registered with threaded irq (%d)\n", chip->irq);
#else
	dev_info(chip->pdev, "registered with irq (%d)\n", chip->irq);
#endif
	/* call init function pointer (this should initialize all registers */
	err = initialize(chip);
	if (err == 0) {
		dev_info(chip->pdev, "Succed to initialize\n");
		return 0;
	}

	dev_err(chip->pdev, "fail to initialize\n");
	}

	return -ENOMEM;
}

/*********************************************************************/
/*! \brief Perform a manual offset calibration
* \param this Pointer to main parent struct
* \return Value return value from the write register
 */
int manual_offset_calibration(psx9500_chip_t chip)
{
	s32 returnValue = 0;

	returnValue = write_register(chip, SX9500_IRQSTAT_REG, 0xFF);
	return returnValue;
}
/*! \brief sysfs show function for manual calibration which currently just
 * returns register value.
 */
static ssize_t manual_offset_calibration_show(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	u8 reg_value = 0;
	psx9500_chip_t chip = dev_get_drvdata(dev);

	dev_dbg(chip->pdev, "Reading IRQSTAT_REG\n");
	read_register(chip, SX9500_IRQSTAT_REG, &reg_value);
	return snprintf(buf, 64, "%d\n", reg_value);
}

/*! \brief sysfs store function for manual calibration
 */
static ssize_t manual_offset_calibration_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	psx9500_chip_t chip = dev_get_drvdata(dev);
	unsigned long val;

	if (kstrtoul(buf, 0, &val))
		return -EINVAL;
	if (val) {
	dev_info(chip->pdev, "Performing manual_offset_calibration()\n");
	SX9500_DBG("%s val=%ld\n", __func__, val);
	manual_offset_calibration(chip);
	}
	return count;
}

static DEVICE_ATTR(calibrate, 0664, manual_offset_calibration_show,
								manual_offset_calibration_store);

unsigned char g_debug_reg = 0;

static ssize_t regval_show(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	psx9500_chip_t chip = dev_get_drvdata(dev);

	unsigned char debug_reg[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x7f};
	int debug_index = 0;
	unsigned char debug_reg_val;
	int reg_count = 0;
	int return_size = 0;

	reg_count = sizeof(debug_reg);
	for (debug_index = 0; debug_index < reg_count; debug_index++) {
		read_register(chip, debug_reg[debug_index], &debug_reg_val);
		/* pr_err("jiangfeng %s, sx9502 reg 0x%x value = 0x%x\n",
		__func__, debug_reg[debug_index], debug_reg_val); */
		return_size += snprintf(buf + return_size, sizeof(buf)-return_size,
		"sx9502 reg 0x%x value = 0x%x\n", debug_reg[debug_index], debug_reg_val);
	}
	/* return sprintf(buf, "success\n"); */
	return return_size;
}

static ssize_t regval_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	psx9500_chip_t chip = dev_get_drvdata(dev);
	unsigned long val;
	unsigned reg_val;

	if (kstrtoul(buf, 0, &val))
		return -EINVAL;
	reg_val = val;
	write_register(chip, g_debug_reg, val);
	return count;
}
static DEVICE_ATTR(regval, 0664, regval_show,
	regval_store);

static ssize_t reg_show(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	return snprintf(buf, 64, "0x%x\n", g_debug_reg);
}

static ssize_t reg_store(struct device *dev, struct device_attribute *attr,
	const char *buf, size_t count)
{
	unsigned long val;

	if (kstrtoul(buf, 0, &val))
		return -EINVAL;

	g_debug_reg = val;

	return count;
}
static DEVICE_ATTR(reg, 0664, reg_show, reg_store);

static ssize_t status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	psx9500_chip_t chip = dev_get_drvdata(dev);
	u8 touchStatus = 0;

	if (socinfo_get_ftm_flag())
		return snprintf(buf, 64, "0\n");

	read_register(chip, SX9500_IRQ_ENABLE_REG, &touchStatus);
	if (!touchStatus)
		return snprintf(buf, 64, "0\n");

	read_register(chip, SX9500_TCHCMPSTAT_REG, &touchStatus);
	if (touchStatus&0x10) {
		return snprintf(buf, 64, "1\n");
	} else {
		return snprintf(buf, 64, "0\n");
	}
}

static DEVICE_ATTR(status, 0664, status_show,
								NULL);

static ssize_t enable_log_show(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	return snprintf(buf, 64, "0x%x\n", g_enable_log);
}

static ssize_t enable_log_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	unsigned long val;
	psx9500_chip_t chip = dev_get_drvdata(dev);

	if (kstrtoul(buf, 0, &val))
		return -EINVAL;

	g_enable_log = val;
	if (g_enable_log)	{
		write_register(chip, SX9500_IRQ_ENABLE_REG, 0x78);
		enable_irq_wake(chip->irq);
	} else {
		write_register(chip, SX9500_IRQ_ENABLE_REG, 0x60);
		disable_irq_wake(chip->irq);
	}

	return count;
}
static DEVICE_ATTR(enable_log, 0664, enable_log_show, enable_log_store);


/*! \brief sysfs show function for enabling irq which currently just
 * returns register value.
 */
static ssize_t enable_sx9500_irq_show(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	u8 reg_value = 0;
	psx9500_chip_t chip = dev_get_drvdata(dev);

	SX9500_DBG("%s enter\n", __func__);
	/* read_register(chip, SX9500_IRQ_ENABLE_REG, &reg_value); */
	reg_value = !(chip->irq_disabled);
	SX9500_DBG("%s return %d\n", __func__, reg_value);
	return snprintf(buf, 64, "%d\n", reg_value);
}

/*! \brief sysfs store function for enabling irq
 */
static ssize_t enable_sx9500_irq_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	psx9500_chip_t chip = dev_get_drvdata(dev);
	unsigned long val;
	struct input_dev *input = NULL;
	u8 touchStatus = 0;

	input = chip->pinput;
	if (kstrtoul(buf, 0, &val))
	return -EINVAL;
	SX9500_DBG("%s enter(val=%ld)\n", __func__, val);

	if (val) {
	SX9500_DBG("%s enable sx9500 disable=%d\n", __func__, chip->irq_disabled);
	if (chip->irq_disabled) {
		if (chip) {
			read_regStat(chip);
			/* msleep(100); */
			read_register(chip, SX9500_TCHCMPSTAT_REG, &touchStatus);
			SX9500_DBG("%s Refresh touch Status %d\n", __func__, touchStatus);
			if (touchStatus&0x10) {
				SX9500_DBG("%s key touch and report\n", __func__);
				input_report_key(input, KEY_F20, 1);
			} else {
				SX9500_DBG("%s key release and report\n", __func__);
				input_report_key(input, KEY_F20, 0);
			}
			input_sync(input);

			/* enable irq */
			enable_irq(chip->irq);
			chip->irq_disabled = 0;
		}
	} else {
		SX9500_DBG("%s have enabled before,so ignore!\n", __func__);
	}

	} else {
	SX9500_DBG("%s disable sx9500 disable=%d\n", __func__, chip->irq_disabled);
	if (!(chip->irq_disabled)) {
		if (chip) {
			SX9500_DBG("%s report far when diabling sar\n", __func__);
			input_report_key(input, KEY_F20, 0);
			input_sync(input);

			/* disable irq */
			disable_irq(chip->irq);
			chip->irq_disabled = 1;
		}
	} else {
		SX9500_DBG("%s have disabled before,so ignore!\n", __func__);
	}
	}
	return count;
}

static DEVICE_ATTR(enable, 0664, enable_sx9500_irq_show, enable_sx9500_irq_store);

/*! \brief sysfs show function for setting threshold which currently just
 * returns register value.
 */
static ssize_t sx9500_set_threshold_show(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	u8 reg_value = 0;
	psx9500_chip_t chip = dev_get_drvdata(dev);

	SX9500_DBG("%s enter\n", __func__);
	read_register(chip, SX9500_CPS_CTRL6_REG, &reg_value);
	SX9500_DBG("%s return %d\n", __func__, reg_value);
	return snprintf(buf, 64, "%d\n", reg_value);
}

/*! \brief sysfs store function for setting threshold
 */
static ssize_t sx9500_set_threshold_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	psx9500_chip_t chip = dev_get_drvdata(dev);
	unsigned long val;

	if (kstrtoul(buf, 0, &val))
	return -EINVAL;
	SX9500_DBG("%s enter(val=%ld)\n", __func__, val);

	if (val >= 0 && val < 32) {
	SX9500_DBG("%s set threshold\n", __func__);
	write_register(chip, SX9500_CPS_CTRL6_REG, val);
	} else {
	SX9500_DBG("%s wrong threshold value!!!\n", __func__);
	}
return count;
}


static DEVICE_ATTR(set_threshold, 0664, sx9500_set_threshold_show, sx9500_set_threshold_store);

int read_regStat(psx9500_chip_t chip)
{
	u8 data = 0;

	if (chip) {
	if (read_register(chip, SX9500_IRQSTAT_REG, &data) == 0)
		return (data & 0x00FF);
	}
return 0;
}

static void hw_init(psx9500_chip_t chip)
{
	int i = 0;
	unsigned char tempval;
	int num = ARRAY_SIZE(sx9500_i2c_reg_setup);

	/* configure device */
	/*pr_err("jiangfeng %s, line %d, enter\n", __func__, __LINE__); */
	dev_dbg(chip->pdev, "Going to Setup I2C Registers\n");
	if (chip) {
		while (i < num) {
		/****
		if (sx9500_i2c_reg_setup[i].reg == SX9500_CPS_CTRL3_REG) {
			if (socinfo_get_pv_flag()) {
				sx9500_i2c_reg_setup[i].val = 0x3;
			}
		}***/
		write_register(chip, sx9500_i2c_reg_setup[i].reg, sx9500_i2c_reg_setup[i].val);
		/*pr_err("jiangfeng %s, line %d, write 0x%x\n",
		__func__, __LINE__, sx9500_i2c_reg_setup[i].val); */
		read_register(chip, sx9500_i2c_reg_setup[i].reg, &tempval);
		/*pr_err("jiangfeng %s, line %d, read 0x%x\n", __func__, __LINE__, tempval); */
		i++;
		}
	} else {
	dev_err(chip->pdev, "ERROR!\n");
	}
}

int initialize(psx9500_chip_t chip)
{
	SX9500_DBG("%s enter\n", __func__);

	if (chip) {
	/* prepare reset by disabling any irq handling */
	chip->irq_disabled = 1;
	disable_irq(chip->irq);
	/* perform a reset */
	/*write_register(chip, SX9500_SOFTRESET_REG, SX9500_SOFTRESET); */
	/* wait until the reset has finished by monitoring NIRQ */
	dev_dbg(chip->pdev, "Sent Software Reset. Waiting until device is back from reset to continue.\n");
	/* just sleep for awhile instead of using a loop with reading irq status */
	msleep(20);
/*	while(chip->get_nirq_low && chip->get_nirq_low()) { read_regStat(chip); } */
	hw_init(chip);
	msleep(50); /* make sure everything is running */
	manual_offset_calibration(chip);

	/* re-enable interrupt handling */
	enable_irq(chip->irq);
	chip->irq_disabled = 0;
	/*enable_irq_wake(chip->irq);*/

	/* make sure no interrupts are pending since enabling irq will only
	 * work on next falling edge */
	read_regStat(chip);
	return 0;
	}
return -ENOMEM;
}

void sx9500_touchProcess(psx9500_chip_t chip)
{
	int counter = 0;
	u8 touchStatus = 0;
	int numberOfButtons = 0;
	struct _buttonInfo *buttons = NULL;
	struct input_dev *input = NULL;

	struct _buttonInfo *pCurrentButton	= NULL;

	SX9500_DBG("%s enter\n", __func__);

	if (chip) {
	dev_dbg(chip->pdev, "Inside %s\n", __func__);
	read_register(chip, SX9500_TCHCMPSTAT_REG, &touchStatus);

	buttons = chip->buttons;
	input = chip->pinput;
	numberOfButtons = chip->buttonSize;

	if (unlikely((buttons == NULL) || (input == NULL))) {
		dev_err(chip->pdev, "ERROR!! buttons or input NULL!!!\n");
		return;
	}

	for (counter = 0; counter < numberOfButtons; counter++) {
		pCurrentButton = &buttons[counter];
		if (pCurrentButton == NULL) {
		dev_err(chip->pdev, "ERROR!! current button at index: %d NULL!!!\n", counter);
		return; /* ERRORR!!!! */
		}
	switch (pCurrentButton->state) {
	case IDLE: /* Button is not being touched! */
		if (((touchStatus & pCurrentButton->mask) == pCurrentButton->mask)) {
		/* User pressed button */
		dev_info(chip->pdev, "cap button %d touched\n", counter);
		SX9500_DBG("%s touch keycode is %d\n", __func__, pCurrentButton->keycode);
		input_report_key(input, pCurrentButton->keycode, 1);
		#ifdef CONFIG_BOARD_JASMINE
		/*write_register(chip, SX9500_CPS_CTRL6_REG, 0x7);*/
		write_register(chip, SX9500_CPS_CTRL6_REG, 0x6);
		#endif
		pCurrentButton->state = ACTIVE;
		} else {
		dev_info(chip->pdev, "Button %d already released.\n", counter);
		}
		break;
	case ACTIVE: /* Button is being touched! */
		if (((touchStatus & pCurrentButton->mask) != pCurrentButton->mask)) {
		/* User released button */
		dev_info(chip->pdev, "cap button %d released\n", counter);
		SX9500_DBG("%s release keycode is %d\n", __func__, pCurrentButton->keycode);
		input_report_key(input, pCurrentButton->keycode, 0);
		#ifdef CONFIG_BOARD_JASMINE
		/*write_register(chip, SX9500_CPS_CTRL6_REG, 0x4);*/
		write_register(chip, SX9500_CPS_CTRL6_REG, 0x3);
		#endif
		pCurrentButton->state = IDLE;
		} else {
		dev_info(chip->pdev, "Button %d still touched.\n", counter);
		}
		break;
	default: /* Shouldn't be here, device only allowed ACTIVE or IDLE */
		break;
		};
	}
	input_sync(input);

		dev_dbg(chip->pdev, "Leaving %s\n", __func__);
		/*pr_err("jiangfeng %s success\n", __func__);*/
		SX9500_DBG("%s success\n", __func__);
	}
}

static int sx9500_parse_dt(psx9500_chip_t chip)
{
	SX9500_DBG("%s enter\n", __func__);
return 0;
}

static int sx9500_fb_callback(struct notifier_block *nfb,
				 unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	int *blank;

	if (evdata && evdata->data && event == FB_EVENT_BLANK) {
		blank = evdata->data;
		if (*blank == FB_BLANK_UNBLANK) {
			if (g_sx9500_chip)
				manual_offset_calibration(g_sx9500_chip);
		}
	}

return 0;
}

static struct notifier_block __refdata sx9500_fb_notifier = {
	.notifier_call = sx9500_fb_callback,
};

static int sx9500_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	int i = 0;
	int ret = 0;
	/*int irq = 0;*/
	psx9500_chip_t chip = 0;
	struct input_dev *input = NULL;
	/*struct device_node *np = client->dev.of_node;*/

	SX9500_DBG("%s enter\n", __func__);
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_SMBUS_READ_WORD_DATA)) {
	SX9500_DBG("%s i2c not support read word data\n", __func__);
	return -EIO;
	}

	chip = kzalloc(sizeof(sx9500_chip_t), GFP_KERNEL); /* create memory for main struct */
	dev_dbg(&client->dev, "\t Initialized Main Memory: 0x%p\n", chip);

	if (chip) {
	chip->bus = client;
	chip->pdev = &client->dev;
	sx9500_parse_dt(chip);

	chip->buttons = psmtcButtons;
	chip->buttonSize = ARRAY_SIZE(psmtcButtons);
	/* shortcut to read status of interrupt */
	/* save irq in case we need to reference it */
	chip->irq = client->irq;
	SX9500_DBG("%s IRQ=%d\n", __func__, chip->irq);
	/* do we need to create an irq timer after interrupt ? */
	/*chip->useIrqTimer = 0;*/

	/* setup i2c communication */
	i2c_set_clientdata(client, chip);

	/* for accessing items in user data (e.g. calibrate) */
	/*sysfs_create_group(&client->dev.kobj, &sx9500_attr_group);*/
	device_create_file(chip->pdev, &dev_attr_calibrate);
	device_create_file(chip->pdev, &dev_attr_enable);
	device_create_file(chip->pdev, &dev_attr_set_threshold);
	device_create_file(chip->pdev, &dev_attr_regval);
	device_create_file(chip->pdev, &dev_attr_reg);
	device_create_file(chip->pdev, &dev_attr_status);
	device_create_file(chip->pdev, &dev_attr_enable_log);

	/* Create the input device */
	input = input_allocate_device();
	if (!input) {
		return -ENOMEM;
	}

	/* Set all the keycodes */
	__set_bit(EV_KEY, input->evbit);
	for (i = 0; i < chip->buttonSize; i++) {
		__set_bit(chip->buttons[i].keycode, input->keybit);
		chip->buttons[i].state = IDLE;
	}
	/* save the input pointer and finish initialization */
	chip->pinput = input;
	input->name = "SX9500 Cap Touch";
	input->id.bustype = BUS_I2C;
	if (input_register_device(input))
		return -ENOMEM;

	chip->pinctrl = devm_pinctrl_get(&client->dev);
	if (IS_ERR_OR_NULL(chip->pinctrl)) {
		/*pr_err("%s, error devm_pinctrl_get(), chip->pinctrl 0x%x\n",
		__func__, (unsigned int)chip->pinctrl);*/
		goto probe_error;
	} else {
		chip->sx9500_active = pinctrl_lookup_state(chip->pinctrl, SSD1306B_ACTIVE);
		if (IS_ERR_OR_NULL(chip->sx9500_active)) {
			pr_err("%s, error pinctrl_lookup_state() for SSD1306B_ACTIVE\n", __func__);
			goto probe_error;
		}
		chip->sx9500_sleep = pinctrl_lookup_state(chip->pinctrl, SSD1306B_SLEEP);
		if (IS_ERR_OR_NULL(chip->sx9500_sleep)) {
			pr_err("%s, error pinctrl_lookup_state() for SSD1306B_SLEEP\n", __func__);
			goto probe_error;
		}
	}

	chip->sx9500_vdd = devm_regulator_get(&client->dev, "vdd");
	if (IS_ERR(chip->sx9500_vdd)) {
		pr_err("unable to get sx9500 vdd\n");
		ret = PTR_ERR(chip->sx9500_vdd);
		chip->sx9500_vdd = NULL;
		goto probe_error;
	}
	chip->sx9500_svdd = devm_regulator_get(&client->dev, "svdd");
	if (IS_ERR(chip->sx9500_vdd)) {
		pr_err("unable to get sx9500 svdd\n");
		ret = PTR_ERR(chip->sx9500_svdd);
		chip->sx9500_svdd = NULL;
		goto probe_error;
	}

#if 0
	ret = of_get_named_gpio(np, "cc,irq_gpio", 0);
	if (ret < 0) {
		pr_err("%s(): error invalid int number	%d\n", __func__, ret);
		goto probe_error;
	} else {
		chip->irq_gpio = ret;
		pr_err("%s(): valid int number	%d\n", __func__, chip->irq_gpio);
	}


	irq = gpio_to_irq(chip->irq_gpio);
	if (irq < 0) {
		pr_err("%s: error gpio_to_irq returned %d\n", __func__, irq);
		goto	probe_error;
	}

	client->irq = irq;
#endif

	sx9500_init(chip);

	g_sx9500_chip = chip;
	fb_register_client(&sx9500_fb_notifier);

	/*printk("jiangfeng %s success\n", __func__);*/
	SX9500_DBG("%s success\n", __func__);
	return	0;
	}

probe_error:
	i2c_set_clientdata(client, NULL);
	return -EPERM;
}

static int sx9500_remove(struct i2c_client *client)
{
	psx9500_chip_t chip = i2c_get_clientdata(client);

	if (chip) {
	input_unregister_device(chip->pinput);
	device_remove_file(chip->pdev, &dev_attr_calibrate);
	device_remove_file(chip->pdev, &dev_attr_enable);
	device_remove_file(chip->pdev, &dev_attr_set_threshold);
	}

	if (chip) {
	cancel_delayed_work_sync(&chip->dworker); /* Cancel the Worker Func */
	/*destroy_workqueue(chip->workq); */
	free_irq(chip->irq, chip);
	kfree(chip);
	return 0;
	}
return -ENOMEM;

}

/*====================================================*/
/***** Kernel Suspend *****/
static int sx9500_suspend(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	psx9500_chip_t chip = i2c_get_clientdata(client);
	/*struct input_dev *input = NULL;*/

	/*input = chip->pinput;*/
	SX9500_DBG("%s enter\n", __func__);
	if (chip) {
	/*SX9310_DBG("%s report far when diabling sar\n", __func__);
	input_report_key(input, KEY_F20, 0);
	input_sync(input);
	disable_irq(chip->irq);
	chip->irq_disabled = 1;*/
	}
return 0;
}

static int sx9500_resume(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	psx9500_chip_t chip = i2c_get_clientdata(client);

	cancel_delayed_work(&chip->resume_worker);
	schedule_delayed_work(&chip->resume_worker, HZ/4);

return 0;
}

static const struct dev_pm_ops sx9500_pm_ops = {
	.suspend	= sx9500_suspend,
	/*.suspend_noirq	= sx9500_suspend_noirq,*/
	.resume		= sx9500_resume,
};

static const struct of_device_id sx9500_match_table[] = {
	{ .compatible = "zte,sx9500-input",},
	{ },
};

static const struct i2c_device_id sx9500_input_id[] = {
	{"sx9500-input", 0},
	{},
};
MODULE_DEVICE_TABLE(i2c, sx9500_driver_id);

static struct i2c_driver sx9500_input_driver = {
	.driver	= {
		.name	= "sx9500-input",
		.owner	= THIS_MODULE,
		.of_match_table	= sx9500_match_table,
		.pm		= &sx9500_pm_ops,
	},
	.probe		= sx9500_probe,
	.remove		= sx9500_remove,
	.id_table	= sx9500_input_id,
};

module_i2c_driver(sx9500_input_driver);

MODULE_DESCRIPTION("sx9500 input");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("i2c:sx9500-input");
