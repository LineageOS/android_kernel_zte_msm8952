/*
 * include/linux/input/sx9500_platform_data.h
 *
 * SX9500 Platform Data
 * 2 cap differential
 *
 * Copyright 2012 Semtech Corp.
 *
 * Licensed under the GPL-2 or later.
 */

#ifndef _SX9500_H_
#define _SX9500_H_

/*registers*/
#define SX9500_IRQSTAT_REG    0x00
#define SX9500_TCHCMPSTAT_REG    0x01
#define SX9500_TOUCH_BIT 0x6
#define SX9500_REASE_BIT 0x5
#define SX9500_IRQ_ENABLE_REG       0x03
#define SX9500_CPS_CTRL0_REG      0x06
#define SX9500_CPS_CTRL1_REG      0x07
#define SX9500_CPS_CTRL2_REG      0x08
#define SX9500_CPS_CTRL3_REG      0x09
#define SX9500_CPS_CTRL4_REG      0x0A
#define SX9500_CPS_CTRL5_REG      0x0B
#define SX9500_CPS_CTRL6_REG      0x0C
#define SX9500_CPS_CTRL7_REG      0x0D
#define SX9500_CPS_CTRL8_REG      0x0E
#define SX9500_SOFTRESET_REG  0x7F

/*Sensor Readback */
#define SX9500_CPSRD          0x20

#define SX9500_USEMSB         0x21
#define SX9500_USELSB         0x22

#define SX9500_AVGMSB         0x23
#define SX9500_AVGLSB         0x24

#define SX9500_DIFFMSB        0x25
#define SX9500_DIFFLSB        0x26

/*IrqStat 0:Inactive 1:Active */
#define SX9500_IRQSTAT_RESET_FLAG      0x80
#define SX9500_IRQSTAT_TOUCH_FLAG      0x40
#define SX9500_IRQSTAT_RELEASE_FLAG    0x20
#define SX9500_IRQSTAT_COMPDONE_FLAG   0x10
#define SX9500_IRQSTAT_CONV_FLAG       0x08
#define SX9500_IRQSTAT_TXENSTAT_FLAG   0x01

/*CpsStat */
#define SX9500_TCHCMPSTAT_TCHSTAT3_FLAG   0x80
#define SX9500_TCHCMPSTAT_TCHSTAT2_FLAG   0x40
#define SX9500_TCHCMPSTAT_TCHSTAT1_FLAG   0x20
#define SX9500_TCHCMPSTAT_TCHSTAT0_FLAG   0x10

/*SoftReset */
#define SX9500_SOFTRESET  0xDE

#define BITGET(byte, bit) (byte & (1 << bit))

struct smtc_reg_data {
unsigned char reg;
unsigned char val;
};
typedef struct smtc_reg_data smtc_reg_data_t;
typedef struct smtc_reg_data *psmtc_reg_data_t;


struct _buttonInfo {
  /*! The Key to send to the input */
int keycode;
  /*! Mask to look for on Touch Status */
int mask;
  /*! Current state of button. */
int state;
};

struct _totalButtonInformation {
struct _buttonInfo *buttons;
int buttonSize;
struct input_dev *input;
};

typedef struct _totalButtonInformation buttonInformation_t;
typedef struct _totalButtonInformation *pbuttonInformation_t;


struct sx9500_platform_data {
pbuttonInformation_t pbuttonInformation;

int (*get_is_nirq_low)(void);

int     (*init_platform_hw)(void);
void    (*exit_platform_hw)(void);
};
typedef struct sx9500_platform_data sx9500_platform_data_t;
typedef struct sx9500_platform_data *psx9500_platform_data_t;

#endif
