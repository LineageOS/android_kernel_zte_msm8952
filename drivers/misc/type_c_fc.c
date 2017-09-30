/* Copyright (c) 2015, The Linux Foundation. All rights reserved.
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

#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/interrupt.h>
#include <linux/power_supply.h>
#include <linux/regulator/consumer.h>

#define TYPEC_CC_I2C_NAME	"usb-typec-cc"
#define TYPEC_CC_I2C_DELAY_MS	100
#define MAX_CURRENT_BC1P2	500
#define MAX_CURRENT_MEDIUM     1500
#define MAX_CURRENT_HIGH       3000

#define TYPEC_CC_1P8_VOL_MAX	1800000 /* uV */

static bool disable_on_suspend;
module_param(disable_on_suspend, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(disable_on_suspend,
	"Whether to disable chip on suspend if state is not attached");

#define TYPE_C_CTL_VENDOR_FAIRCHILD 0x12
#define TYPE_C_CTL_VENDOR_TI 0x30
#define TYPE_C_CTL_VENDOR_PERICOM 0x00
#define TYPE_C_CTL_VENDOR_UNKNOWN 0xff

#define PI_CCD_DEFAULT		0x1
#define PI_CCD_MEDIUM		0x2
#define PI_CCD_HIGH		0x3

struct piusb_regs {
	u8		dev_id;
	u8		control;
	u8		intr_status;
#define	INTS_ATTACH	0x1
#define	INTS_DETACH	0x2
#define INTS_ATTACH_MASK	0x3   /* current attach state interrupt */

	u8		port_status;
#define STS_PORT_MASK	(0x1c)	      /* attached port status  - device/host */
#define STS_CCD_MASK	(0x60)	      /* charging current status */
#define STS_VBUS_MASK	(0x80)	      /* vbus status */
} __packed;

#define TI_CCD_DEFAULT		0x0
#define TI_CCD_MEDIUM		0x1
#define TI_CCD_HIGH		0x3
#define TI_CCD_MASK		(0x30)	      /* charging current status */
#define TI_INTS_ATTACH_MASK	(0xC0)   /* current attach state interrupt */
#define TI_ATTACH_TO_DFP	0x2	 /* configured as UFP attaches to DFP */
#define TI_STS_8_REG		0x8
#define TI_STS_9_REG		0x9
#define TI_INTS_STATUS		BIT(4)

#define TI_STS_9_ATTACH_SHIFT 6
#define TI_STS_9_ATTACH  (0x03 << TI_STS_9_ATTACH_SHIFT)
#define TI_STS_9_CC  0x20

struct tiusb_regs {
	u8			status_8_reg;
	u8			status_9_reg;
} __packed;

struct typec_cc {
	struct i2c_client	*client;
	struct power_supply	*usb_psy;
	int			max_current;
	bool			attach_state;
	int			enb_gpio;
	int			enb_gpio_polarity;
	int			int_gpio;
	struct regulator	*i2c_1p8;
	u8          vendr_id;
	struct pinctrl			*pinctrl;
	struct pinctrl_state		*gpio_state_active;
	bool enable_usb30;
};
static struct typec_cc *typec_cc_data = NULL;
static int ldo_use_count = 0;
int enb_gpio = -1;
int enb_gpio_polarity = 1;

static int typec_cc_i2c_read_regs(struct typec_cc *typec_cc, u8 *buf, int len)
{
	int rc;
	struct i2c_client *i2c = typec_cc->client;
	uint16_t saddr = i2c->addr;
	struct i2c_msg msgs[] = {
		{
			.addr  = saddr,
			.flags = I2C_M_RD,
			.len   = len,
			.buf   = (u8 *)buf,
		}
	};

	rc = i2c_transfer(i2c->adapter, msgs, 1);
	if (rc < 0) {
		/* i2c read may fail if device not enabled or not present */
		dev_dbg(&i2c->dev, "[Pericom] i2c read from 0x%x failed %d\n", saddr, rc);
		return -ENXIO;
	}
	return rc;
}

static int typec_cc_update_power_supply(struct power_supply *psy, int limit)
{
	const union power_supply_propval ret = {limit,};

	/* Update USB of max charging current (500 corresponds to bc1.2 */
	if (psy->set_property)
		return psy->set_property(psy,
			POWER_SUPPLY_PROP_INPUT_CURRENT_MAX, &ret);

	return -ENODEV;
}

static int typec_cc_i2c_write(struct typec_cc *typec_cc, u8 *data, int len)
{
	int ret;
	struct i2c_client *i2c = typec_cc->client;
	uint16_t saddr = i2c->addr;
	struct i2c_msg msgs[] = {
		{
			.addr  = saddr,
			.flags = 0,
			.len   = len,
			.buf   = data,
		}
	};

	ret = i2c_transfer(i2c->adapter, msgs, 1);
	if (ret != 1) {
		dev_dbg(&i2c->dev, "i2c write to [%x] failed %d\n",
				saddr, ret);
		return -EIO;
	}
	return 0;
}

static int typec_cc_i2c_read(struct typec_cc *typec_cc, u8 *data, int len)
{
	int ret;
	struct i2c_client *i2c = typec_cc->client;
	uint16_t saddr = i2c->addr;
	struct i2c_msg msgs[] = {
		{
			.addr  = saddr,
			.flags = I2C_M_RD,
			.len   = len,
			.buf   = data,
		}
	};

	ret = i2c_transfer(i2c->adapter, msgs, 1);
	if (ret != 1) {
		dev_dbg(&i2c->dev, "i2c read [%x] failed %d\n",
				saddr, ret);
		return -EIO;
	}
	return 0;
}

static void typec_cc_piusb_update_max_current(struct typec_cc *typec_cc, struct piusb_regs	*reg_data)
{
	u8 mask = STS_CCD_MASK;
	u8 shift = find_first_bit((void *)&mask, 8);
	u8 chg_mode = reg_data->port_status & mask;

	chg_mode >>= shift;

	/* update to 0 if type-c detached */
	if (!typec_cc->attach_state) {
		typec_cc->max_current = 0;
		return;
	}

	switch (chg_mode) {
	case PI_CCD_DEFAULT:
		typec_cc->max_current = MAX_CURRENT_BC1P2;
		break;
	case PI_CCD_MEDIUM:
		typec_cc->max_current = MAX_CURRENT_MEDIUM;
		break;
	case PI_CCD_HIGH:
		typec_cc->max_current = MAX_CURRENT_HIGH;
		break;
	default:
		dev_dbg(&typec_cc->client->dev, "[Pericom] wrong chg mode %x\n", chg_mode);
		typec_cc->max_current = MAX_CURRENT_BC1P2;
	}

	dev_dbg(&typec_cc->client->dev, "[Pericom] chg mode: %x, mA:%u\n", chg_mode,
							typec_cc->max_current);
}

static irqreturn_t typec_cc_piusb_irq(int irq, void *data)
{
	int ret;
	struct typec_cc *typec_cc = (struct typec_cc *)data;
	struct piusb_regs	reg_data;
	u8 attach_state;

	/* i2c register update takes time, 30msec sleep required as per HPG */
	msleep(TYPEC_CC_I2C_DELAY_MS);

	ret = typec_cc_i2c_read_regs(typec_cc, (u8 *)&reg_data, sizeof(reg_data));
	if (ret < 0)
		goto pi_out;

	dev_info(&typec_cc->client->dev, "[Pericom] i2c read from 0x%x-[%x %x %x %x]\n",
		typec_cc->client->addr,
		reg_data.dev_id, reg_data.control,
		reg_data.intr_status, reg_data.port_status);

	if (!reg_data.intr_status) {
		dev_err(&typec_cc->client->dev, "[Pericom] intr_status is 0!, ignore interrupt\n");
		typec_cc->attach_state = false;
		goto pi_out;
	}

	attach_state = reg_data.intr_status & INTS_ATTACH_MASK;
	typec_cc->attach_state = (attach_state == INTS_ATTACH) ? true : false;

	typec_cc_piusb_update_max_current(typec_cc, &reg_data);

	ret = typec_cc_update_power_supply(typec_cc->usb_psy, typec_cc->max_current);
	if (ret < 0)
		dev_err(&typec_cc->client->dev, "[Pericom] failed to notify USB-%d\n", ret);

pi_out:
	return IRQ_HANDLED;
}

static void typec_cc_tiusb_update_max_current(struct typec_cc *typec_cc, struct tiusb_regs	*reg_data)
{
	u8 mask = TI_CCD_MASK;
	u8 shift = find_first_bit((void *)&mask, 8);
	u8 chg_mode = reg_data->status_8_reg & mask;

	chg_mode >>= shift;

	/* update to 0 if type-c UFP detached */
	if (typec_cc->attach_state != TI_ATTACH_TO_DFP) {
		dev_dbg(&typec_cc->client->dev, "[TI] attach_state: %x\n",
						typec_cc->attach_state);
		typec_cc->max_current = 0;
		return;
	}

	switch (chg_mode) {
	case TI_CCD_DEFAULT:
		typec_cc->max_current = MAX_CURRENT_BC1P2;
		break;
	case TI_CCD_MEDIUM:
		typec_cc->max_current = MAX_CURRENT_MEDIUM;
		break;
	case TI_CCD_HIGH:
		typec_cc->max_current = MAX_CURRENT_HIGH;
		break;
	default:
		dev_dbg(&typec_cc->client->dev, "[TI] wrong chg mode %x\n", chg_mode);
		typec_cc->max_current = 500;
	}

	dev_dbg(&typec_cc->client->dev, "[TI] chg mode: %x, mA:%u, attach: %x\n",
			chg_mode, typec_cc->max_current, typec_cc->attach_state);
}


static irqreturn_t typec_cc_ti_irq(int irq, void *data)
{
	int rc;
	struct typec_cc *typec_cc = (struct typec_cc *)data;
	struct i2c_client *i2c = typec_cc->client;
	uint16_t saddr = i2c->addr;
	u8 attach_state, mask = TI_INTS_ATTACH_MASK;
	struct tiusb_regs	reg_data;

	rc = i2c_smbus_read_byte_data(i2c, TI_STS_8_REG);
	if (rc < 0)
		goto ti_out;
	reg_data.status_8_reg = rc;

	rc = i2c_smbus_read_byte_data(i2c, TI_STS_9_REG);
	if (rc < 0)
		goto ti_out;
	reg_data.status_9_reg = rc;

	/* Clear interrupt */
	rc = i2c_smbus_write_byte_data(i2c, TI_STS_9_REG, reg_data.status_9_reg);
	if (rc < 0)
		goto ti_out;

	dev_dbg(&i2c->dev, "[TI] i2c read from 0x%x-[0x%x 0x%x]\n", saddr,
				reg_data.status_8_reg, reg_data.status_9_reg);

	if (!(reg_data.status_9_reg & TI_INTS_STATUS)) {
		dev_err(&i2c->dev, "[TI] intr_status is 0!, ignore interrupt\n");
		typec_cc->attach_state = false;
		goto ti_out;
	}

	attach_state = reg_data.status_9_reg & mask;
	typec_cc->attach_state = attach_state >> find_first_bit((void *)&mask, 8);

	switch ((reg_data.status_9_reg & TI_STS_9_ATTACH) >> TI_STS_9_ATTACH_SHIFT) {
	case 0x00:
		dev_info(&i2c->dev, "REG9:Not attached---\n");
		break;
	case 0x01:
		dev_info(&i2c->dev, "REG9:Attached.SRC(DFP)+++\n");
		break;
	case 0x02:
		dev_info(&i2c->dev, "REG9:Attached.SNK(UFP)+++\n");
		break;
	case 0x03:
		dev_info(&i2c->dev, "REG9:Attached to an accessory+++\n");
		break;
	}

	if (typec_cc->attach_state) {
		dev_info(&i2c->dev, "REG9:%s connected\n",
		(reg_data.status_9_reg & TI_STS_9_CC) ? "CC2(default)" : "CC1");
	}

	typec_cc_tiusb_update_max_current(typec_cc, &reg_data);

	rc = typec_cc_update_power_supply(typec_cc->usb_psy, typec_cc->max_current);
	if (rc < 0)
		dev_err(&typec_cc->client->dev, "[TI] failed to notify USB-%d\n", rc);
ti_out:
	return IRQ_HANDLED;
}

#define FC_STATUS_REG		0x11
#define FC_TYPE_REG			0x12
#define FC_INT_REG			0x13
static irqreturn_t typec_cc_fc_irq(int irq, void *data)
{
	int rc;
	struct typec_cc *typec_cc = (struct typec_cc *)data;
	struct i2c_client *i2c = typec_cc->client;

	rc = i2c_smbus_read_byte_data(i2c, FC_INT_REG);
	if (rc >= 0)
		dev_dbg(&i2c->dev, "FC int reg [0x%02x]\n", rc);

	if (!(rc & 0x0F)) {
		dev_err(&i2c->dev, "FC INT reg is 0!, ignore interrupt\n");
		return IRQ_HANDLED;
	}

	if (rc & 0x01)
		dev_info(&i2c->dev, "FC Type C connected ++++++\n");
	if (rc & 0x02) {
		dev_info(&i2c->dev, "FC Type C diconnected ++++++\n");
		return IRQ_HANDLED;
	}
	if (rc & 0x04)
		dev_info(&i2c->dev, "FC Type C BC_LVL changed\n");
	if (rc & 0x08)
		dev_info(&i2c->dev, "FC Type C Acc changed\n");

	rc = i2c_smbus_read_byte_data(i2c, FC_TYPE_REG);
	if (rc >= 0)
		dev_dbg(&i2c->dev, "FC type reg [0x%02x]\n", rc);

	if (rc & 0x10) {
		dev_info(&i2c->dev, "FC Source Role\n");
	} else if (rc & 0x08) {
		dev_info(&i2c->dev, "FC Sink Role\n");
	} else if (rc & 0x07) {
		dev_info(&i2c->dev, "FC Accessory Role\n");
	}

	rc = i2c_smbus_read_byte_data(i2c, FC_STATUS_REG);
	if (rc >= 0)
		dev_dbg(&i2c->dev, "FC status reg [0x%02x]\n", rc);

	dev_info(&i2c->dev, "FC Vbus %d, Attach %d\n", (rc & 0x08) >> 3, rc & 0x01);
	if ((rc & 0x30) == 0x10)
		dev_info(&i2c->dev, "FC CC1 connected\n");
	else if ((rc & 0x30) == 0x20)
		dev_info(&i2c->dev, "FC CC2 connected\n");

	return IRQ_HANDLED;
}

static irqreturn_t typec_cc_irq(int irq, void *data)
{
	struct typec_cc *typec_cc = (struct typec_cc *)data;
	struct i2c_client *i2c = typec_cc->client;

	switch (i2c->addr) {
	case 0x3d:
		return typec_cc_piusb_irq(irq, data);
	case 0x61:
		return typec_cc_ti_irq(irq, data);
	case 0x25:
		return typec_cc_fc_irq(irq, data);
	default:
		return IRQ_HANDLED;
	}
}


static int typec_cc_read_vendor_id(struct typec_cc *typec_cc)
{
	int ret = 0;
	u8 reg[2] = {0};
	u8 id;

	switch (typec_cc->client->addr) {
	case 0x3d:    /* pericom */
		ret = typec_cc_i2c_read(typec_cc, reg, 2);
		if (ret != 0) {
			dev_dbg(&typec_cc->client->dev, "failed to read vendor id reg [%d]\n", ret);
			return ret;
		}

		id = reg[1];
		break;

	case 0x61:    /* ti */
		reg[0] = 0x00;
		ret = typec_cc_i2c_write(typec_cc, reg, 1);
		if (ret != 0) {
			dev_dbg(&typec_cc->client->dev, "failed to write vendor id reg [%d]\n", ret);
			return ret;
		}

		ret = typec_cc_i2c_read(typec_cc, reg, 1);
		if (ret != 0) {
			dev_dbg(&typec_cc->client->dev, "failed to read vendor id reg [%d]\n", ret);
			return ret;
		}

		id = reg[0];
		break;

	case 0x25:    /* fairchild */
		reg[0] = 0x01;
		ret = typec_cc_i2c_write(typec_cc, reg, 1);
		if (ret != 0) {
			dev_dbg(&typec_cc->client->dev, "failed to write vendor id reg [%d]\n", ret);
			return ret;
		}

		ret = typec_cc_i2c_read(typec_cc, reg, 1);
		if (ret != 0) {
			dev_dbg(&typec_cc->client->dev, "failed to read vendor id reg [%d]\n", ret);
			return ret;
		}

		id = reg[0];
		break;
	default:
		return -EINVAL;
	}

	if (id != TYPE_C_CTL_VENDOR_FAIRCHILD
		&& id != TYPE_C_CTL_VENDOR_TI
		&& id != TYPE_C_CTL_VENDOR_PERICOM) {
		dev_err(&typec_cc->client->dev, "Invalid vendor id, vend id = 0x%02x\n", id);
		id = TYPE_C_CTL_VENDOR_UNKNOWN;
		return -EINVAL;
	}

	typec_cc->vendr_id = id;
	dev_info(&typec_cc->client->dev, "vend id = 0x%02x\n", typec_cc->vendr_id);

	return ret;
}


static int typec_cc_i2c_enable(struct typec_cc *typec_cc, bool enable)
{
	switch (typec_cc->client->addr) {
	case 0x3d:
		{
			u8 rst_assert[] = {0, 0x1};
			u8 rst_deassert[] = {0, 0x4};
			u8 pi_disable[] = {0, 0x80};

			if (!enable) {
				if (typec_cc_i2c_write(typec_cc, pi_disable, sizeof(pi_disable)))
					return -EIO;
				return 0;
			}

			if (typec_cc_i2c_write(typec_cc, rst_assert, sizeof(rst_assert)))
				return -EIO;

			msleep(TYPEC_CC_I2C_DELAY_MS);
			return typec_cc_i2c_write(typec_cc, rst_deassert, sizeof(rst_deassert));
		}
		break;
	case 0x61:
		break;
	case 0x25:
		{
			if (enable) {
				u8 fc_drp[] = {0x02, 0x10};
				u8 fc_ctl[] = {0x03, 0x02};
				u8 fc_mask[] = {0x10, 0x0C};

				if (typec_cc_i2c_write(typec_cc, fc_drp, sizeof(fc_drp)))
					return -EIO;
				if (typec_cc_i2c_write(typec_cc, fc_ctl, sizeof(fc_ctl)))
					return -EIO;
				if (typec_cc_i2c_write(typec_cc, fc_mask, sizeof(fc_mask)))
					return -EIO;
			}
		}
		break;
	default:
		dev_err(&typec_cc->client->dev, "Error, unknown vend id %x\n", typec_cc->vendr_id);
	}

	return 0;
}

static int typec_cc_gpio_config(struct typec_cc *typec_cc, bool init)
{
	int ret = 0;

	if (!gpio_is_valid(typec_cc->enb_gpio) || !gpio_is_valid(typec_cc->int_gpio))
		return -ENODEV;

	if (init) {
		/* EN gpio */
		ret = devm_gpio_request(&typec_cc->client->dev, typec_cc->enb_gpio,
						"typec_cc_enb");
		if (ret) {
			pr_err("unable to request gpio [%d]\n", typec_cc->enb_gpio);
			goto out;
		}

		ret = gpio_direction_output(typec_cc->enb_gpio, typec_cc->enb_gpio_polarity);
		if (ret) {
			dev_err(&typec_cc->client->dev, "set output[%d] failed for gpio[%d]\n",
				typec_cc->enb_gpio_polarity, typec_cc->enb_gpio);
			goto free_enb;
		}
		dev_dbg(&typec_cc->client->dev, "set output[%d] for gpio[%d]\n",
				typec_cc->enb_gpio_polarity, typec_cc->enb_gpio);

		/* INT gpio */
		ret = devm_gpio_request(&typec_cc->client->dev, typec_cc->int_gpio,
						"typec_cc_int");
		if (ret) {
			pr_err("unable to request gpio [%d]\n", typec_cc->int_gpio);
			goto free_enb;
		}

		ret = gpio_direction_input(typec_cc->int_gpio);
		if (ret) {
			dev_err(&typec_cc->client->dev, "set input failed for gpio[%d]\n", typec_cc->int_gpio);
			goto free_int;
		}

		msleep(TYPEC_CC_I2C_DELAY_MS);
	} else
		goto free_int;

	return 0;

free_int:
	devm_gpio_free(&typec_cc->client->dev, typec_cc->int_gpio);
free_enb:
	devm_gpio_free(&typec_cc->client->dev, typec_cc->enb_gpio);
out:
	return ret;
}

static int typec_cc_ldo_init(struct typec_cc *typec_cc, bool init)
{
	int rc = 0;

	if (IS_ERR(typec_cc->i2c_1p8)) {
		rc = PTR_ERR(typec_cc->i2c_1p8);
		dev_err(&typec_cc->client->dev, "unable to get 1p8(%d)\n", rc);
		return rc;
	}

	if (!init) {
		ldo_use_count--;
		if (ldo_use_count == 0) {
			regulator_set_voltage(typec_cc->i2c_1p8, 0, TYPEC_CC_1P8_VOL_MAX);
			rc = regulator_disable(typec_cc->i2c_1p8);
		}
		return rc;
	}

	ldo_use_count++;
	if (ldo_use_count > 1) {
		return 0;
	}

	rc = regulator_set_voltage(typec_cc->i2c_1p8, TYPEC_CC_1P8_VOL_MAX,
					TYPEC_CC_1P8_VOL_MAX);
	if (rc) {
		dev_err(&typec_cc->client->dev, "unable to set voltage(%d)\n", rc);
		goto put_1p8;
	}

	rc = regulator_enable(typec_cc->i2c_1p8);
	if (rc) {
		dev_err(&typec_cc->client->dev, "unable to enable 1p8-reg(%d)\n", rc);
		return rc;
	}

	return 0;

put_1p8:
	regulator_set_voltage(typec_cc->i2c_1p8, 0, TYPEC_CC_1P8_VOL_MAX);
	return rc;
}

static void typec_cc_parse_dt(struct typec_cc *typec_cc, struct device_node *np)
{
	enum of_gpio_flags flags;

	/* override with module-param */
	if (!disable_on_suspend)
		disable_on_suspend = of_property_read_bool(np,
						"typec_cc,disable-on-suspend");

	typec_cc->enb_gpio = enb_gpio = of_get_named_gpio_flags(np, "typec_cc,enb-gpio", 0,
							&flags);

	if (!gpio_is_valid(typec_cc->enb_gpio)) {
		dev_dbg(&typec_cc->client->dev, "enb gpio_get fail:%d\n", typec_cc->enb_gpio);
	} else {
		typec_cc->enb_gpio_polarity = enb_gpio_polarity = !(flags & OF_GPIO_ACTIVE_LOW);
	}

	typec_cc->int_gpio = of_get_named_gpio_flags(np, "typec_cc,int-gpio", 0, &flags);
	typec_cc->enable_usb30 = of_property_read_bool(np, "typec_cc,enable-usb30");
	typec_cc->i2c_1p8 = devm_regulator_get(&typec_cc->client->dev, "vdd_io");
}

static int typec_cc_probe(struct i2c_client *i2c, const struct i2c_device_id *id)
{
	int ret;
	struct power_supply *usb_psy;
	struct device_node *np = i2c->dev.of_node;
	struct typec_cc *typec_cc;

	if (typec_cc_data != NULL) {
		return -ENODEV;
	}

	usb_psy = power_supply_get_by_name("usb");
	if (!usb_psy) {
		dev_dbg(&i2c->dev, "USB power_supply not found, defer probe\n");
		return -EPROBE_DEFER;
	}

	typec_cc = devm_kzalloc(&i2c->dev, sizeof(struct typec_cc),
				GFP_KERNEL);
	if (!typec_cc) {
		return -ENOMEM;
	}

	i2c_set_clientdata(i2c, typec_cc);
	typec_cc->client = i2c;
	typec_cc->usb_psy = usb_psy;

	if (i2c->irq < 0) {
		dev_err(&i2c->dev, "irq not defined (%d)\n", i2c->irq);
		ret = -EINVAL;
		goto out;
	}

	typec_cc_parse_dt(typec_cc, np);

	ret = typec_cc_gpio_config(typec_cc, true);
	if (ret)
		goto out;

	ret = typec_cc_ldo_init(typec_cc, true);
	if (ret) {
		dev_err(&typec_cc->client->dev, "i2c ldo init failed\n");
		goto gpio_disable;
	}

	ret = typec_cc_read_vendor_id(typec_cc);
	if (ret) {
		dev_err(&typec_cc->client->dev, "Get vendor ID failed\n");
		goto ldo_disable;
	}

	ret = typec_cc_i2c_enable(typec_cc, true);
	if (ret) {
		dev_err(&typec_cc->client->dev, "i2c access failed\n");
		goto ldo_disable;
	}

	if (typec_cc->enable_usb30) {
		/* Update initial state to USB */
		typec_cc_irq(i2c->irq, typec_cc);

		ret = devm_request_threaded_irq(&i2c->dev, i2c->irq, NULL, typec_cc_irq,
						IRQF_ONESHOT | IRQF_TRIGGER_FALLING,
						TYPEC_CC_I2C_NAME, typec_cc);
		if (ret) {
			dev_err(&i2c->dev, "irq(%d) req failed-%d\n", i2c->irq, ret);
			goto i2c_disable;
		}
	}

	dev_err(&i2c->dev, "%s finished, addr:0x%02x\n", __func__, i2c->addr);
	typec_cc_data = typec_cc;
	return 0;

i2c_disable:
	typec_cc_i2c_enable(typec_cc, false);
ldo_disable:
	typec_cc_ldo_init(typec_cc, false);
gpio_disable:
	typec_cc_gpio_config(typec_cc, false);
out:
	devm_kfree(&i2c->dev, typec_cc);
	typec_cc_data = NULL;
	return ret;
}

static int typec_cc_remove(struct i2c_client *i2c)
{
	struct typec_cc *typec_cc = i2c_get_clientdata(i2c);

	typec_cc_i2c_enable(typec_cc, false);
	typec_cc_ldo_init(typec_cc, false);
	typec_cc_gpio_config(typec_cc, false);
	devm_kfree(&i2c->dev, typec_cc);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int typec_cc_i2c_suspend(struct device *dev)
{
	struct i2c_client *i2c = to_i2c_client(dev);
	struct typec_cc *typec_cc = i2c_get_clientdata(i2c);

	dev_dbg(dev, "typec cc PM suspend.. attach(%d) disable(%d)\n",
			typec_cc->attach_state, disable_on_suspend);

	disable_irq(typec_cc->client->irq);

	/* Keep type-c chip enabled during session */
	if (typec_cc->attach_state)
		return 0;

	if (disable_on_suspend) {
		typec_cc_i2c_enable(typec_cc, false);
		/* power off the V1.8 */
		regulator_set_voltage(typec_cc->i2c_1p8, 0, TYPEC_CC_1P8_VOL_MAX);
		regulator_disable(typec_cc->i2c_1p8);
		/* Pulldown the EN gpio */
		gpio_set_value(typec_cc->enb_gpio, !typec_cc->enb_gpio_polarity);
	}

	return 0;
}

static int typec_cc_i2c_resume(struct device *dev)
{
	int rc;
	struct i2c_client *i2c = to_i2c_client(dev);
	struct typec_cc *typec_cc = i2c_get_clientdata(i2c);

	dev_dbg(dev, "typec cc PM resume\n");

	/* suspend was no-op, just re-enable interrupt */
	if (typec_cc->attach_state) {
		enable_irq(typec_cc->client->irq);
		return 0;
	}

	if (disable_on_suspend) {
		gpio_set_value(typec_cc->enb_gpio, typec_cc->enb_gpio_polarity);
		msleep(TYPEC_CC_I2C_DELAY_MS);

		rc = regulator_set_voltage(typec_cc->i2c_1p8, TYPEC_CC_1P8_VOL_MAX,
						TYPEC_CC_1P8_VOL_MAX);
		if (rc)
			dev_err(&typec_cc->client->dev, "unable to set voltage(%d)\n", rc);

		rc = regulator_enable(typec_cc->i2c_1p8);
		if (rc)
			dev_err(&typec_cc->client->dev, "unable to enable 1p8-reg(%d)\n", rc);


		rc = typec_cc_i2c_enable(typec_cc, true);
	}
	enable_irq(typec_cc->client->irq);

	return rc;
}


static SIMPLE_DEV_PM_OPS(typec_cc_i2c_pm_ops, typec_cc_i2c_suspend,
			  typec_cc_i2c_resume);
#endif
static const struct i2c_device_id typec_cc_id[] = {
	{ TYPEC_CC_I2C_NAME, 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, piusb_id);

#ifdef CONFIG_OF
static const struct of_device_id typec_cc_usb_of_match[] = {
	{ .compatible = "fusb301,usb-type-c", },
	{},
};
MODULE_DEVICE_TABLE(of, piusb_of_match);
#endif

static struct i2c_driver typec_cc_usb_driver = {
	.driver = {
		.name = TYPEC_CC_I2C_NAME,
		.of_match_table = of_match_ptr(typec_cc_usb_of_match),
#ifdef CONFIG_PM_SLEEP
		.pm	= &typec_cc_i2c_pm_ops,
#endif
	},
	.probe		= typec_cc_probe,
	.remove		= typec_cc_remove,
	.id_table	= typec_cc_id,
};

module_i2c_driver(typec_cc_usb_driver);

MODULE_DESCRIPTION("TypeC CC Detection driver");
MODULE_LICENSE("GPL v2");
