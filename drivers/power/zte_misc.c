/*
 * Driver for zte misc functions
 * function1: used for translate hardware GPIO to SYS GPIO number
 * function2: update fingerprint status to kernel from fingerprintd,2016/01/18
 */

#include <linux/module.h>

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/sched.h>
#include <linux/pm.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/workqueue.h>
#include <linux/gpio.h>
#include <linux/of_platform.h>
#include <linux/of_gpio.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/delay.h>
#include <linux/power_supply.h>
#include <soc/qcom/socinfo.h>

#define CHARGER_BUF_SIZE 0x2
/*
  *Emode function to enable/disable 0% shutdown
  */
int enable_to_shutdown = 1;
static int set_enable_to_shutdown(const char *val, struct kernel_param *kp)
{
	int ret;

	ret = param_set_int(val, kp);
	if (ret) {
		pr_err("error setting value %d\n", ret);
		return ret;
	}

	pr_warn("set_enable_to_shutdown to %d\n", enable_to_shutdown);
	return 0;
}

module_param_call(enable_to_shutdown, set_enable_to_shutdown, param_get_uint,
					&enable_to_shutdown, 0644);

static int zte_misc_charging_enabled;
static int zte_misc_control_charging(const char *val, struct kernel_param *kp)
{
	struct power_supply	*batt_psy;
	int rc;
	const union power_supply_propval enable = {1,};
	const union power_supply_propval disable = {0,};

	rc = param_set_int(val, kp);
	if (rc) {
		pr_err("%s: error setting value %d\n", __func__, rc);
		return rc;
	}

	batt_psy = power_supply_get_by_name("battery");
	if (batt_psy) {
		if (zte_misc_charging_enabled != 0) {
			rc = batt_psy->set_property(batt_psy,
					POWER_SUPPLY_PROP_CHARGING_ENABLED, &enable);
			pr_info("%s: enable charging\n", __func__);
		} else {
			rc = batt_psy->set_property(batt_psy,
					POWER_SUPPLY_PROP_CHARGING_ENABLED, &disable);
			pr_info("%s: disable charging\n", __func__);
		}
		if (rc) {
			pr_err("battery does not export CHARGING_ENABLED: %d\n", rc);
		}
	} else
		pr_err("%s: batt_psy is NULL\n", __func__);

	return 0;
}
static int zte_misc_get_charging_enabled_node(char *val, struct kernel_param *kp)
{
	struct power_supply	*batt_psy;
	int rc;
	union power_supply_propval pval = {0,};

	batt_psy = power_supply_get_by_name("battery");
	if (batt_psy) {
		rc = batt_psy->get_property(batt_psy,
					POWER_SUPPLY_PROP_CHARGING_ENABLED, &pval);
			pr_info("%s: enable charging status %d\n", __func__, pval.intval);
		if (rc) {
			pr_err("battery charging_enabled node is not exist: %d\n", rc);
			return  snprintf(val, CHARGER_BUF_SIZE, "%d", -1);
		}
		zte_misc_charging_enabled = pval.intval;
	} else
		pr_err("%s: batt_psy is NULL\n", __func__);

	return  snprintf(val, CHARGER_BUF_SIZE, "%d", pval.intval);
}

module_param_call(charging_enabled, zte_misc_control_charging, zte_misc_get_charging_enabled_node,
					&zte_misc_charging_enabled, 0644);
/* The same as the definitions in ap\hardware\libhardware\include\hardware\Fingerprint.h */
typedef enum fingerprint_msg_type {
	FINGERPRINT_ERROR = -1,
	FINGERPRINT_ACQUIRED = 1,
	FINGERPRINT_TEMPLATE_ENROLLING = 3,
	FINGERPRINT_TEMPLATE_REMOVED = 4,
	FINGERPRINT_AUTHENTICATED = 5,
	FINGERPRINT_DETECTED = 6,
	FINGERPRINT_REMOVED = 7,
} fingerprint_msg_type_t;

/* fp_msg_disable: set to 1 to disable lcd accelerator, for debug */
static int fp_msg_disable = 0;
static int fp_msg_type = FINGERPRINT_ERROR;

extern void fb_blank_update_oem(void);/* defined in drivers\video\fbdev\core\fbmem.c */
static int fp_msg_type_set(const char *val, struct kernel_param *kp)
{
	int ret;

	ret = param_set_int(val, kp);
	if (ret) {
		pr_err("zte_misc: error setting value %d\n", ret);
		goto error;
	}
	pr_info("zte_misc: set fp_msg_type to %d, fp_msg_disable=%d\n", fp_msg_type, fp_msg_disable);
	if (fp_msg_disable == 1)
		return 0;

	if (fp_msg_type == FINGERPRINT_DETECTED) {
		pr_info("zte_misc: fp_msg_set acquired\n");
		fb_blank_update_oem();
	}

	return 0;
error:
	return ret;
}
module_param_call(fp_msg_type, fp_msg_type_set, param_get_int, &fp_msg_type, 0644);
module_param(fp_msg_disable, int, 0644);

static int zte_misc_probe(struct platform_device *pdev)
{
	/* struct device *dev = &pdev->dev; */

	pr_info("zte_misc: %s +++++\n", __func__);

	/* zte_misc_fingerprint_hw_check(dev); */

	pr_info("zte_misc: %s ----\n", __func__);
	return 0;
}

static int  zte_misc_remove(struct platform_device *pdev)
{
	return 0;
}

static struct platform_driver zte_misc_driver = {
	.probe      = zte_misc_probe,
	.remove    = zte_misc_remove,
	.driver     = {
		.name   = "zte-misc",
		.owner  = THIS_MODULE,
		/* .of_match_table = zte_misc_of_match, */
	}
};
static struct platform_device zte_misc_device = {
	.name = "zte-misc",
	.id = -1,
};


int __init zte_misc_init(void)
{
	int ret;

	pr_info("zte_misc: %s entry\n", __func__);

	/* register device */
	ret = platform_device_register(&zte_misc_device);
	if (ret) {
		pr_err("%s,platform_device_register failed!\n", __func__);
		goto out;
	}
	/* register driver */
	ret = platform_driver_register(&zte_misc_driver);
	if (ret < 0) {
		pr_err("%s,platform_driver_register failed\n", __func__);
		goto out;
	}

out:
	return ret;
}

static void __exit zte_misc_exit(void)
{
	platform_device_unregister(&zte_misc_device);
	platform_driver_unregister(&zte_misc_driver);
}
fs_initcall(zte_misc_init);
module_exit(zte_misc_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Misc driver for zte");
MODULE_ALIAS("platform:zte-misc");
