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
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_fdt.h>
#include <linux/uaccess.h>
#include <linux/platform_device.h>
#include <linux/notifier.h>
#include <linux/miscdevice.h>
#include <soc/qcom/scm.h>
#include <soc/qcom/smem.h>
#include "../../smem_private.h"


#define VLOG_MEMORY_ADDR_PROP "qcom,msm-imem-vlog_memory_addr"
#define VLOG_MEMORY_SIZE_PROP "qcom,msm-imem-vlog_memory_size"
#define VLOG_MEMORY_COOK_PROP "qcom,msm-imem-vlog_memory_cookie"


#define VENDOR_LOG_NAME					"vlog"
#define VENDOR_LOG_QUEUE        "vlog_work_queue"
#define VENDOR_LOG_CHECK_INTERVAL         (10000)
#define VENDOR_LOG_BUFFER_COOKIE          (0x37734664)
#define VENDOR_LOG_SMEM_RETRIES           (5)
#define VENDOR_LOG_COOKIE                 0x20160919

#define VENDOR_LOG_4K_ALINED_ADDR(x)      (x & 0xFFFFD000)
#define VENDOR_LOG_4K_ADDR_OFFSET(x)      (x & 0x1FFF)
#define SIZE_4K                           (0x1000)


#define VENDOR_LOG_OFFSET(x, size)    (x%size)


#define VENDOR_LOG_LOST_FORMAT    "\n-----lost %d bytes data----\n"
#define VENDOR_LOG_LOST_LEN    (100)

struct vendor_log_phys_addr_info_type {
	unsigned int phys_addr_cookie;
	unsigned int phys_addr;
	unsigned int size;
	unsigned int total_log_length;
};

struct vendor_log_type {
	struct vendor_log_phys_addr_info_type     *head_ptr;
	unsigned char                             *data_ptr;
};




struct vendor_log_device {
	struct miscdevice device;
	unsigned int data_ready;
	unsigned int consumer_present;
	struct workqueue_struct *vlog_workqueue;
	struct delayed_work vlog_check_log;
	struct vendor_log_type     vlog_mem_info;
	unsigned int        read_bytes;
	unsigned int        available_bytes;
	wait_queue_head_t   read_wait_q;
	int                 smem_initialized;
	unsigned int        *vlog_imem_addr;
	unsigned int        *vlog_imem_size;
	unsigned int        *vlog_imem_cookie;
	unsigned int        vlog_memory_addr;
	unsigned int        vlog_memory_size;
};



static int vlog_open(struct inode *inode, struct file *filep);
static int vlog_release(struct inode *inode, struct file *filep);
static ssize_t vlog_read(struct file *filep, char __user *buf,
	size_t count, loff_t *pos);
static int vendor_log_init_notifier(struct notifier_block *this,
	unsigned long code, void *_cmd);
static int vendor_log_vote_smem_init(void);


static int vlog_status;
static int vlog_flush_interval = VENDOR_LOG_CHECK_INTERVAL;
static int tickes;
static int detail_log = 0;


static struct vendor_log_device vlog_device;

static const struct file_operations vendor_log_file_ops = {
	.open = vlog_open,
	.release = vlog_release,
	.read = vlog_read,
};

static struct notifier_block nb = {
	.notifier_call = vendor_log_init_notifier,
};


#define log_info(fmt, ...) \
	do { \
		if (detail_log) \
			pr_info(fmt, ##__VA_ARGS__); \
	} while (0)


static int vlog_status_set(const char *val, struct kernel_param *kp);
module_param_call(vlog_status, vlog_status_set, param_get_int,
			&vlog_status, 0644);

module_param(vlog_flush_interval, int, S_IRUGO | S_IWUSR);


static int vlog_status_set(const char *val, struct kernel_param *kp)
{
	int ret;
	int old_val = vlog_status;

	pr_info("vlog_status_set old vlog_status %d\n", vlog_status);

	ret = param_set_int(val, kp);
	pr_info("vlog_status_set new vlog_status %d\n", vlog_status);

	if (ret)
		return ret;

	/* If vlog_status is not zero or one, ignore. */
	if (vlog_status >> 1) {
		vlog_status = old_val;
		return -EINVAL;
	}


	if (vlog_status && !old_val) {
		vendor_log_vote_smem_init();
		schedule_delayed_work(&(vlog_device.vlog_check_log),
			msecs_to_jiffies(vlog_flush_interval));
	}

	return 0;
}


static int vendor_log_update_buffer_info(unsigned long addr,  size_t size)
{
	struct dma_attrs attrs;

	init_dma_attrs(&attrs);
	dma_set_attr(DMA_ATTR_SKIP_ZEROING, &attrs);

	vlog_device.vlog_mem_info.data_ptr =
		(unsigned char *)dma_remap(NULL, NULL, addr, size, &attrs);

	if (!vlog_device.vlog_mem_info.data_ptr) {
		pr_err("%s: can not map the addr 0x%lx  error\n",
			__func__, addr);
		return -ENOMEM;
	}

	pr_info("%s: map the addr 0x%lx aligned_addr 0x%lx  size %zd\n",
		__func__, (unsigned long)vlog_device.vlog_mem_info.data_ptr,
		addr, size);
	return 0;

}


static int vendor_log_smem_init(void)
{
	if (!vlog_device.vlog_mem_info.head_ptr) {
		vlog_device.vlog_mem_info.head_ptr =
			(struct vendor_log_phys_addr_info_type *)
			smem_alloc(SMEM_ID_VENDOR2,
			sizeof(struct vendor_log_phys_addr_info_type),	0,
			SMEM_ANY_HOST_FLAG);
		if (!vlog_device.vlog_mem_info.head_ptr) {
			pr_err("%s: smem_alloc SMEM_ID_VENDOR2	error\n",
				__func__);
			return -ENOMEM;
		}
	}

	if ((vlog_device.vlog_mem_info.head_ptr->phys_addr_cookie ==
			VENDOR_LOG_BUFFER_COOKIE)
			&& (vlog_device.vlog_memory_addr) &&
			(vlog_device.vlog_memory_size != 0)) {
		pr_info("%s: phys_addr is 0x%x, size is 0x%x\n",
			__func__, vlog_device.vlog_memory_addr,
			vlog_device.vlog_memory_size);
		if (!vendor_log_update_buffer_info(vlog_device.vlog_memory_addr,
				vlog_device.vlog_memory_size)) {
			vlog_device.smem_initialized = 1;
			return 0;
		}
	}
	pr_info("%s: smem initialized %d\n", __func__,
		vlog_device.smem_initialized);
	return -ENOMEM;
}

static int vendor_log_vote_smem_init(void)
{
	tickes--;
	if (tickes == 0)
		return vendor_log_smem_init();

	return 0;
}

static int vendor_log_init_notifier(
	struct notifier_block *this,
	unsigned long code,
	void *_cmd)
{
	pr_info("vendor_log_init_notifier\n");
	return vendor_log_vote_smem_init();
}


static int is_buffer_roll_back(
	unsigned int read_bytes,
	unsigned int available_bytes)
{
	if ((read_bytes/vlog_device.vlog_memory_size) ==
			(available_bytes/vlog_device.vlog_memory_size)) {
		return 0;
	}

	return 1;
}

static int is_buffer_over_load(
	unsigned int read_bytes,
	unsigned int available_bytes)
{
	return (available_bytes-read_bytes) >
		vlog_device.vlog_memory_size ? 1:0;
}



static int vlog_open(struct inode *inode, struct file *filep)
{
	struct vendor_log_device *vlog_dev = container_of(filep->private_data,
				struct vendor_log_device, device);
	if (!vlog_dev->smem_initialized) {
		pr_info("%s smem do not initialized ", __func__);
		return -EPERM;
	}

	vlog_dev->consumer_present = 1;
	pr_info("%s enter", __func__);
	return 0;
}

static int vlog_release(struct inode *inode, struct file *filep)
{
	struct vendor_log_device *vlog_dev = container_of(filep->private_data,
		struct vendor_log_device, device);
	vlog_dev->consumer_present = 0;
	vlog_dev->data_ready = 0;
	pr_info("%s enter", __func__);
	return 0;
}

static int vlog_secure_copy(char *alignbuf, char *logbuff, size_t count)
{
	unsigned long bytes_before, bytes_after;
	unsigned char *device_mem = NULL;
	size_t alignsize;

	device_mem = logbuff;
	alignsize = count;

	if ((unsigned long)logbuff & 0x7) {
		bytes_before = 8 - ((unsigned long)device_mem & 0x7);
		memcpy_fromio(alignbuf, device_mem, bytes_before);
		device_mem += bytes_before;
		alignbuf += bytes_before;
		alignsize -= bytes_before;
	}

	if (alignsize & 0x7) {
		bytes_after = alignsize & 0x7;
		memcpy(alignbuf, device_mem, alignsize - bytes_after);
		device_mem += alignsize - bytes_after;
		alignbuf += (alignsize - bytes_after);
		alignsize = bytes_after;
		memcpy_fromio(alignbuf, device_mem, alignsize);
	} else {
		memcpy(alignbuf, device_mem, alignsize);
	}

	return 0;

}

static ssize_t vlog_read_in_buffer_roll(
	struct vendor_log_device *vlog_dev,
	char *buf, size_t count)
{
	size_t copy_size = 0;
	size_t data_left_size = 0;
	int ret = 0;

	data_left_size = vlog_dev->vlog_memory_size -
		VENDOR_LOG_OFFSET(vlog_dev->read_bytes,
		vlog_dev->vlog_memory_size);
	if (count > data_left_size) {
		if (vlog_secure_copy(buf,
				vlog_dev->vlog_mem_info.data_ptr +
				VENDOR_LOG_OFFSET(vlog_dev->read_bytes,
				vlog_dev->vlog_memory_size), data_left_size)) {
			ret = -EFAULT;
			goto read_done;
		}

		if (VENDOR_LOG_OFFSET(vlog_dev->available_bytes,
						vlog_dev->vlog_memory_size) >=
						(count-data_left_size)) {
			if (vlog_secure_copy(buf+data_left_size,
					vlog_dev->vlog_mem_info.data_ptr,
					count - data_left_size)) {
				ret = -EFAULT;
				goto read_done;
			}
			copy_size = count;
		} else{
			if (vlog_secure_copy(buf+data_left_size,
					vlog_dev->vlog_mem_info.data_ptr,
					VENDOR_LOG_OFFSET(
					vlog_dev->available_bytes,
					vlog_dev->vlog_memory_size) -
					data_left_size)) {
				ret = -EFAULT;
				goto read_done;
			}
			copy_size = vlog_dev->available_bytes -
							vlog_dev->read_bytes;
		}

		return copy_size;
	}
	if (vlog_secure_copy(buf, vlog_dev->vlog_mem_info.data_ptr +
			VENDOR_LOG_OFFSET(vlog_device.read_bytes,
			vlog_dev->vlog_memory_size), count)) {
		ret = -EFAULT;
		goto read_done;
	}
	return count;

read_done:
	return ret;
}


static ssize_t vlog_read(struct file *filep, char __user *buf, size_t count,
			loff_t *pos)
{
	struct vendor_log_device *vlog_dev = container_of(filep->private_data,
				struct vendor_log_device, device);
	size_t copy_size = 0;
	unsigned char *alignbuf = NULL;
	int ret = 0;

	log_info("%s enter count %d", __func__, (int)count);

	if (filep->f_flags & O_NONBLOCK) {
		pr_info("%s f_flags do not contain O_NONBLOCK", __func__);
		return -EAGAIN;
	}

	ret = wait_event_interruptible(vlog_dev->read_wait_q,
					vlog_dev->data_ready);
	if (ret) {
		pr_info("%s wait_event_interruptible error", __func__);
		return ret;
	}
	vlog_dev->available_bytes =
		vlog_dev->vlog_mem_info.head_ptr->total_log_length;
	log_info("%s data ready %d, ",  __func__, vlog_dev->available_bytes);
	if (vlog_dev->read_bytes >= vlog_dev->available_bytes) {
		pr_info("already read %d, total log data %d bytes",
		vlog_dev->read_bytes,
		vlog_dev->vlog_mem_info.head_ptr->total_log_length);
		return 0;
	}

	copy_size = min((size_t)(vlog_dev->available_bytes -
			vlog_dev->read_bytes), count);
	alignbuf = kzalloc(copy_size, GFP_KERNEL);
	if (!alignbuf) {
		pr_err("vendor_log: Unable to alloc mem for aligned buf");
		ret = -ENOMEM;
		goto read_done;
	}

	if (is_buffer_roll_back(vlog_dev->read_bytes,
				vlog_dev->available_bytes) == 0) {
		copy_size = vlog_dev->available_bytes - vlog_dev->read_bytes;
		copy_size = min(copy_size, count);

		if (vlog_secure_copy(alignbuf,
				vlog_dev->vlog_mem_info.data_ptr +
				VENDOR_LOG_OFFSET(vlog_dev->read_bytes,
					vlog_dev->vlog_memory_size),
				copy_size)) {
			ret = -EFAULT;
			goto read_done;
		}

		vlog_dev->read_bytes += copy_size;
	} else if (is_buffer_over_load(vlog_dev->read_bytes,
			vlog_dev->available_bytes)) {
		char lost[VENDOR_LOG_LOST_LEN] = {0};
		int len = 0;

		pr_err("vendor_log: is_buffer_over_load");
		len = snprintf(lost, sizeof(lost), VENDOR_LOG_LOST_FORMAT,
			vlog_dev->available_bytes - vlog_dev->read_bytes -
			vlog_dev->vlog_memory_size);
		if (len < 0) {
			ret = -EFAULT;
			goto read_done;
		}

		if (vlog_secure_copy(alignbuf, lost, len)) {
			ret = -EFAULT;
			goto read_done;
		}

		copy_size = vlog_read_in_buffer_roll(vlog_dev,
			alignbuf+len,
			count - len);
		if (copy_size < 0) {
			ret = -EFAULT;
			goto read_done;
		}

		vlog_dev->read_bytes = vlog_dev->available_bytes -
			vlog_dev->vlog_memory_size + copy_size;
	} else{
		copy_size = vlog_read_in_buffer_roll(vlog_dev, alignbuf, count);
		vlog_dev->read_bytes += copy_size;
	}

	if (copy_to_user(buf, alignbuf, copy_size)) {
		ret = -EFAULT;
		goto read_done;
	}

	if (copy_size < count)
		vlog_dev->data_ready = 0;

	ret = copy_size;
read_done:

	kfree(alignbuf);
	return ret;
}

static void vlog_check_log_work_fn(struct work_struct *work)
{
	static int smem_init_retries = VENDOR_LOG_SMEM_RETRIES;

	log_info("%s:  enter\n", __func__);
	if (!vlog_device.smem_initialized) {
		log_info("%s: smem does not finish init\n", __func__);
		if (vendor_log_smem_init() < 0) {
			smem_init_retries--;
			goto exit;
		}
	}

	vlog_device.available_bytes =
		vlog_device.vlog_mem_info.head_ptr->total_log_length;
	log_info("%s:  total_log_length %d,  buffer_length %d read_bytes %d\n",
		__func__, vlog_device.vlog_mem_info.head_ptr->total_log_length,
		vlog_device.vlog_mem_info.head_ptr->size,
		vlog_device.read_bytes);
	if (vlog_device.vlog_mem_info.head_ptr->total_log_length <= 0) {
		log_info("%s: no data find\n", __func__);
		goto exit;
	}

	if (vlog_device.read_bytes < vlog_device.available_bytes) {
		vlog_device.data_ready = 1;
		if (vlog_device.consumer_present) {
			log_info("%s:	enter\n", __func__);
			wake_up(&vlog_device.read_wait_q);
		}
	}

exit:
	if (vlog_status && (smem_init_retries > 0)) {
		schedule_delayed_work(&(vlog_device.vlog_check_log),
			msecs_to_jiffies(vlog_flush_interval));
	}
}



int create_log_device(const char *dev_name)
{
	int ret;

	if (!dev_name) {
		pr_err("%s: Invalid device name.\n", __func__);
		return -EINVAL;
	}

	vlog_device.device.minor = MISC_DYNAMIC_MINOR;
	vlog_device.device.name = dev_name;
	vlog_device.device.fops = &vendor_log_file_ops;
	vlog_device.device.parent = NULL;

	init_waitqueue_head(&vlog_device.read_wait_q);
	ret = misc_register(&vlog_device.device);
	if (ret) {
		pr_err("%s: misc_register failed for %s (%d)",
			__func__, dev_name, ret);
		return ret;
	}
	return 0;
}


static int __init vlog_scan_reserved_mem(
	unsigned long node,
	const char *uname,
	int depth,
	void *data)
{
	int ret = of_flat_dt_is_compatible(node, "removed_vlog_memory");
	const unsigned int *reg;
	int l;

	if (!ret)
		return 0;

	reg = of_get_flat_dt_prop(node, "reg", &l);
	if (reg == NULL) {
		pr_err("vlog_scan_reserved_mem REG NULL\n");
		return 0;
	}


	*vlog_device.vlog_imem_addr = be32_to_cpu(reg[1]);
	*vlog_device.vlog_imem_size = be32_to_cpu(reg[3]);
	*vlog_device.vlog_imem_cookie = VENDOR_LOG_COOKIE;

	vlog_device.vlog_memory_addr = *vlog_device.vlog_imem_addr;
	vlog_device.vlog_memory_size = *vlog_device.vlog_imem_size;

	pr_info("memory scan node %s, reg size %d, data: 0x%x 0x%x 0x%x 0x%x 0x%x,\n",
			uname, l, reg[0], *vlog_device.vlog_imem_addr, reg[2],
			*vlog_device.vlog_imem_size,
			*vlog_device.vlog_imem_cookie);

	return 1;

}


unsigned int vendor_log_get_memory_addr(void)
{
	return vlog_device.vlog_memory_addr;
}


unsigned int vendor_log_get_memory_size(void)
{
	return vlog_device.vlog_memory_size;
}


static void vendor_log_imem_init(void)
{
	struct device_node *np;

	np = of_find_compatible_node(NULL, NULL, VLOG_MEMORY_ADDR_PROP);
	if (!np) {
		pr_err("unable to find DT imem vlog addr node\n");
		return;
	}
	vlog_device.vlog_imem_addr = of_iomap(np, 0);
	if (!vlog_device.vlog_imem_addr) {
		pr_err("unable to map imem vlog memory addr offset\n");
		return;
	}

	np = of_find_compatible_node(NULL, NULL, VLOG_MEMORY_SIZE_PROP);
	if (!np) {
		pr_err("unable to find DT imem vlog size node\n");
		return;
	}
	vlog_device.vlog_imem_size = of_iomap(np, 0);
	if (!vlog_device.vlog_imem_size) {
		pr_err("unable to map imem vlog memory size\n");
		return;
	}


	np = of_find_compatible_node(NULL, NULL, VLOG_MEMORY_COOK_PROP);
	if (!np) {
		pr_err("unable to find DT imem vlog size node\n");
		return;
	}
	vlog_device.vlog_imem_cookie = of_iomap(np, 0);
	if (!vlog_device.vlog_imem_cookie) {
		pr_err("unable to map imem vlog memory cookie\n");
		return;
	}
	pr_info("map imem vlog memory cookie and reset the value\n");
	*vlog_device.vlog_imem_cookie = 0;


	of_scan_flat_dt(vlog_scan_reserved_mem, NULL);

}

static __init int vendor_log_late_init(void)
{
	pr_info("vendor_log_late_init\n");

	tickes = 2;

	memset(&vlog_device, 0, sizeof(vlog_device));

	vendor_log_imem_init();

	if (create_log_device(VENDOR_LOG_NAME) < 0) {
		pr_err("%s: create_log_device error ",  __func__);
		return -ENOMEM;
	}

	vlog_device.vlog_workqueue =
		create_singlethread_workqueue(VENDOR_LOG_QUEUE);
	if (!vlog_device.vlog_workqueue) {
		pr_err("%s: create_singlethread_workqueue error\n", __func__);
		return -ENOMEM;
	}

	INIT_DELAYED_WORK(&(vlog_device.vlog_check_log),
		vlog_check_log_work_fn);

	smem_module_init_notifier_register(&nb);
	return 0;
}



late_initcall(vendor_log_late_init);

MODULE_DESCRIPTION("Vendor Log Driver");
MODULE_LICENSE("GPL v2");
