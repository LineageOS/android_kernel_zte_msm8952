ccflags-y += -Idrivers/media/platform/msm/camera_v2/sensor/cci
ccflags-y += -Idrivers/media/platform/msm/camera_v2
ccflags-y += -Idrivers/media/platform/msm/camera_v2/sensor/io
obj-$(CONFIG_MSMB_CAMERA) += msm_led_flash.o
obj-$(CONFIG_MSMB_CAMERA) += msm_led_trigger.o
obj-$(CONFIG_MSMB_CAMERA) += msm_led_i2c_trigger.o
ifneq ($(CONFIG_BOARD_TULIP),y)
obj-$(CONFIG_MSMB_CAMERA) += adp1660.o
obj-$(CONFIG_MSMB_CAMERA) += bd7710.o
endif
obj-$(CONFIG_MSMB_CAMERA) += msm_led_torch.o
obj-$(CONFIG_MSMB_CAMERA) += msm_flash.o
ifeq ($(CONFIG_BOARD_TULIP),y)
obj-$(CONFIG_MSMB_CAMERA) += lm3646.o
else
obj-$(CONFIG_MSMB_CAMERA) += lm3642.o
endif
