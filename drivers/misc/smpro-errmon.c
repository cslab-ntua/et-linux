// SPDX-License-Identifier: GPL-2.0+
/*
 * Ampere Computing SoC's SMpro Error Monitoring Driver
 *
 * Copyright (c) 2022, Ampere Computing LLC
 *
 */

#include <linux/i2c.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

/* GPI RAS Error Registers */
#define GPI_RAS_ERR		0x7E

/* Core and L2C Error Registers */
#define CORE_CE_ERR_CNT		0x80
#define CORE_CE_ERR_LEN		0x81
#define CORE_CE_ERR_DATA	0x82
#define CORE_UE_ERR_CNT		0x83
#define CORE_UE_ERR_LEN		0x84
#define CORE_UE_ERR_DATA	0x85

/* Memory Error Registers */
#define MEM_CE_ERR_CNT		0x90
#define MEM_CE_ERR_LEN		0x91
#define MEM_CE_ERR_DATA		0x92
#define MEM_UE_ERR_CNT		0x93
#define MEM_UE_ERR_LEN		0x94
#define MEM_UE_ERR_DATA		0x95

/* RAS Error/Warning Registers */
#define ERR_SMPRO_TYPE		0xA0
#define ERR_PMPRO_TYPE		0xA1
#define ERR_SMPRO_INFO_LO	0xA2
#define ERR_SMPRO_INFO_HI	0xA3
#define ERR_SMPRO_DATA_LO	0xA4
#define ERR_SMPRO_DATA_HI	0xA5
#define WARN_SMPRO_INFO_LO	0xAA
#define WARN_SMPRO_INFO_HI	0xAB
#define ERR_PMPRO_INFO_LO	0xA6
#define ERR_PMPRO_INFO_HI	0xA7
#define ERR_PMPRO_DATA_LO	0xA8
#define ERR_PMPRO_DATA_HI	0xA9
#define WARN_PMPRO_INFO_LO	0xAC
#define WARN_PMPRO_INFO_HI	0xAD

/* PCIE Error Registers */
#define PCIE_CE_ERR_CNT		0xC0
#define PCIE_CE_ERR_LEN		0xC1
#define PCIE_CE_ERR_DATA	0xC2
#define PCIE_UE_ERR_CNT		0xC3
#define PCIE_UE_ERR_LEN		0xC4
#define PCIE_UE_ERR_DATA	0xC5

/* Other Error Registers */
#define OTHER_CE_ERR_CNT	0xD0
#define OTHER_CE_ERR_LEN	0xD1
#define OTHER_CE_ERR_DATA	0xD2
#define OTHER_UE_ERR_CNT	0xD8
#define OTHER_UE_ERR_LEN	0xD9
#define OTHER_UE_ERR_DATA	0xDA

/* Event Data Registers */
#define VRD_WARN_FAULT_EVENT_DATA	0x78
#define VRD_HOT_EVENT_DATA		0x79
#define DIMM_HOT_EVENT_DATA		0x7A
#define DIMM_2X_REFRESH_EVENT_DATA	0x96

#define MAX_READ_BLOCK_LENGTH	48
#define NUM_I2C_MESSAGES	2
#define MAX_MSG_LEN		128

#define RAS_SMPRO_ERRS		0
#define RAS_PMPRO_ERRS		1

enum RAS_48BYTES_ERR_TYPES {
	CORE_CE_ERRS,
	CORE_UE_ERRS,
	MEM_CE_ERRS,
	MEM_UE_ERRS,
	PCIE_CE_ERRS,
	PCIE_UE_ERRS,
	OTHER_CE_ERRS,
	OTHER_UE_ERRS,
	NUM_48BYTES_ERR_TYPE,
};

struct smpro_error_hdr {
	u8 err_count;	/* Number of the RAS errors */
	u8 err_len;	/* Number of data bytes */
	u8 err_data;	/* Start of 48-byte data */
	u8 max_err_cnt;	/* Max num of errors */
};

/*
 * Included Address of registers to get Count, Length of data and Data
 * of the 48 bytes error data
 */
static struct smpro_error_hdr smpro_error_table[NUM_48BYTES_ERR_TYPE] = {
	{CORE_CE_ERR_CNT, CORE_CE_ERR_LEN, CORE_CE_ERR_DATA, 32},
	{CORE_UE_ERR_CNT, CORE_UE_ERR_LEN, CORE_UE_ERR_DATA, 32},
	{MEM_CE_ERR_CNT, MEM_CE_ERR_LEN, MEM_CE_ERR_DATA, 16},
	{MEM_UE_ERR_CNT, MEM_UE_ERR_LEN, MEM_UE_ERR_DATA, 16},
	{PCIE_CE_ERR_CNT, PCIE_CE_ERR_LEN, PCIE_CE_ERR_DATA, 96},
	{PCIE_UE_ERR_CNT, PCIE_UE_ERR_LEN, PCIE_UE_ERR_DATA, 96},
	{OTHER_CE_ERR_CNT, OTHER_CE_ERR_LEN, OTHER_CE_ERR_DATA, 8},
	{OTHER_UE_ERR_CNT, OTHER_UE_ERR_LEN, OTHER_UE_ERR_DATA, 8},
};

/*
 * List of SCP registers which are used to get
 * one type of RAS Internal errors.
 */
struct smpro_int_error_hdr {
	u8 err_type;
	u8 err_info_low;
	u8 err_info_high;
	u8 err_data_high;
	u8 err_data_low;
	u8 warn_info_low;
	u8 warn_info_high;
};

static struct smpro_int_error_hdr list_smpro_int_error_hdr[2] = {
	{
	 ERR_SMPRO_TYPE,
	 ERR_SMPRO_INFO_LO, ERR_SMPRO_INFO_HI,
	 ERR_SMPRO_DATA_LO, ERR_SMPRO_DATA_HI,
	 WARN_SMPRO_INFO_LO, WARN_SMPRO_INFO_HI
	},
	{
	 ERR_PMPRO_TYPE,
	 ERR_PMPRO_INFO_LO, ERR_PMPRO_INFO_HI,
	 ERR_PMPRO_DATA_LO, ERR_PMPRO_DATA_HI,
	 WARN_PMPRO_INFO_LO, WARN_PMPRO_INFO_HI
	},
};

struct smpro_errmon {
	struct regmap *regmap;
};

enum EVENT_TYPES {
	VRD_WARN_FAULT_EVENTS,
	VRD_HOT_EVENTS,
	DIMM_HOT_EVENTS,
	NUM_EVENTS_TYPE,
};

/* Included Address of event source and data registers */
static u8 smpro_event_table[NUM_EVENTS_TYPE] = {
	VRD_WARN_FAULT_EVENT_DATA,
	VRD_HOT_EVENT_DATA,
	DIMM_HOT_EVENT_DATA,
};

static ssize_t smpro_event_data_read(struct device *dev,
				     struct device_attribute *da, char *buf,
				     int channel)
{
	struct smpro_errmon *errmon = dev_get_drvdata(dev);
	s32 event_data;
	int ret;

	ret = regmap_read(errmon->regmap, smpro_event_table[channel], &event_data);
	if (ret)
		goto done;

	ret = sysfs_emit(buf, "%02x%04x\n", channel, event_data);
	/* Clear event after read */
	if (event_data != 0)
		regmap_write(errmon->regmap, smpro_event_table[channel], event_data);
done:
	return ret;
}

static ssize_t smpro_overflow_data_read(struct device *dev, struct device_attribute *da,
					char *buf, int channel)
{
	struct smpro_errmon *errmon = dev_get_drvdata(dev);
	struct smpro_error_hdr *err_info;
	s32 err_count;
	int ret;

	err_info = &smpro_error_table[channel];

	ret = regmap_read(errmon->regmap, err_info->err_count, &err_count);
	if (ret)
		return ret;

	/* Bit 8 indicates the overflow status */
	return sysfs_emit(buf, "%d\n", (err_count & BIT(8)) ? 1 : 0);
}

static ssize_t smpro_error_data_read(struct device *dev, struct device_attribute *da,
				     char *buf, int channel)
{
	struct smpro_errmon *errmon = dev_get_drvdata(dev);
	unsigned char err_data[MAX_READ_BLOCK_LENGTH];
	struct smpro_error_hdr *err_info;
	s32 err_count, err_length;
	int count = 0;
	int ret;

	err_info = &smpro_error_table[channel];

	ret = regmap_read(errmon->regmap, err_info->err_count, &err_count);
	/* Error count is the low byte */
	err_count &= 0xff;
	if (ret || !err_count || err_count > err_info->max_err_cnt)
		goto done;

	ret = regmap_read(errmon->regmap, err_info->err_len, &err_length);
	if (ret || err_length <= 0)
		goto done;

	if (err_length > MAX_READ_BLOCK_LENGTH)
		err_length = MAX_READ_BLOCK_LENGTH;

	memset(err_data, 0x00, MAX_READ_BLOCK_LENGTH);
	ret = regmap_noinc_read(errmon->regmap, err_info->err_data, err_data, err_length);
	if (ret < 0)
		goto done;

	/*
	 * The output of Core/Memory/PCIe/Others UE/CE errors follows below format:
	 * <Error Type><Error SubType><Instance><Error Status>\
	 * <Error Address><Error Misc 0><Error Misc 1><Error Misc2><Error Misc 3>
	 * Where:
	 *  + Error Type: The hardwares cause the errors. (1 byte)
	 *  + SubType: Sub type of error in the specified hardware error. (1 byte)
	 *  + Instance: Combination of the socket, channel,
	 *    slot cause the error. (2 bytes)
	 *  + Error Status: Encode of error status. (4 bytes)
	 *  + Error Address: The address in device causes the errors. (8 bytes)
	 *  + Error Misc 0/1/2/3: Addition info about the errors. (8 bytes for each)
	 * Reference Altra SOC BMC Interface specification.
	 */
	count = sysfs_emit(buf, "%02x%02x%04x%08x%016llx%016llx%016llx%016llx%016llx\n",
			   err_data[0], err_data[1], *(u16 *)&err_data[2],
			   *(u32 *)&err_data[4], *(u64 *)&err_data[8],
			   *(u64 *)&err_data[16], *(u64 *)&err_data[24],
			   *(u64 *)&err_data[32], *(u64 *)&err_data[40]);

	/* go to next error */
	ret = regmap_write(errmon->regmap, err_info->err_count, 0x100);
done:
	return ret ? ret : count;
}

/*
 * Output format:
 * <errType><image><dir><Location><errorCode><data>
 * Where:
 *   + errType: SCP Error Type (3 bits)
 *      1: Warning
 *      2: Error
 *      4: Error with data
 *   + image: SCP Image Code (8 bits)
 *   + dir: Direction (1 bit)
 *      0: Enter
 *      1: Exit
 *   + location: SCP Module Location Code (8 bits)
 *   + errorCode: SCP Error Code (16 bits)
 *   + data : Extensive data (32 bits)
 *      All bits are 0 when errType is warning or error.
 */
static ssize_t smpro_internal_err_read(struct device *dev, struct device_attribute *da,
				       char *buf, int channel)
{
	struct smpro_errmon *errmon = dev_get_drvdata(dev);
	struct smpro_int_error_hdr *err_info;
	unsigned int data_lo = 0, data_hi = 0;
	unsigned int ret_hi, ret_lo;
	unsigned int err_type;
	unsigned int value;
	int count = 0;
	int ret;

	/* read error status */
	ret = regmap_read(errmon->regmap, GPI_RAS_ERR, &value);
	if (ret)
		goto done;

	if (!((channel == RAS_SMPRO_ERRS && (value & BIT(0))) ||
	      (channel == RAS_PMPRO_ERRS && (value & BIT(1)))))
		goto done;

	err_info = &list_smpro_int_error_hdr[channel];
	ret = regmap_read(errmon->regmap, err_info->err_type, &err_type);
	if (ret)
		goto done;

	ret = regmap_read(errmon->regmap, err_info->err_info_low, &ret_lo);
	if (ret)
		goto done;

	ret = regmap_read(errmon->regmap, err_info->err_info_high, &ret_hi);
	if (ret)
		goto done;

	if (err_type & BIT(2)) {
		/* Error with data type */
		ret = regmap_read(errmon->regmap, err_info->err_data_low, &data_lo);
		if (ret)
			goto done;

		ret = regmap_read(errmon->regmap, err_info->err_data_high, &data_hi);
		if (ret)
			goto done;

		count = sysfs_emit(buf, "%01x%02x%01x%02x%04x%04x%04x\n",
				   4, (ret_hi & 0xf000) >> 12, (ret_hi & 0x0800) >> 11,
				   ret_hi & 0xff, ret_lo, data_hi, data_lo);
		/* clear the read errors */
		ret = regmap_write(errmon->regmap, err_info->err_type, BIT(2));

	} else if (err_type & BIT(1)) {
		/* Error type */
		count = sysfs_emit(buf, "%01x%02x%01x%02x%04x%04x%04x\n",
				   2, (ret_hi & 0xf000) >> 12, (ret_hi & 0x0800) >> 11,
				   ret_hi & 0xff, ret_lo, data_hi, data_lo);
		/* clear the read errors */
		ret = regmap_write(errmon->regmap, err_info->err_type, BIT(1));

	} else if (err_type & BIT(0)) {
		/* Warning type */
		count = sysfs_emit(buf, "%01x%02x%01x%02x%04x%04x%04x\n",
				   1, (ret_hi & 0xf000) >> 12, (ret_hi & 0x0800) >> 11,
				   ret_hi & 0xff, ret_lo, data_hi, data_lo);
		/* clear the read errors */
		ret = regmap_write(errmon->regmap, err_info->err_type, BIT(0));
	}
done:
	return ret ? ret : count;
}

#define ERROR_OVERFLOW_RO(_error, _index) \
	static ssize_t overflow_##_error##_show(struct device *dev,            \
						struct device_attribute *da,   \
						char *buf)                     \
	{                                                                      \
		return smpro_overflow_data_read(dev, da, buf, _index);         \
	}                                                                      \
	static DEVICE_ATTR_RO(overflow_##_error)

ERROR_OVERFLOW_RO(core_ce, CORE_CE_ERRS);
ERROR_OVERFLOW_RO(core_ue, CORE_UE_ERRS);
ERROR_OVERFLOW_RO(mem_ce, MEM_CE_ERRS);
ERROR_OVERFLOW_RO(mem_ue, MEM_UE_ERRS);
ERROR_OVERFLOW_RO(pcie_ce, PCIE_CE_ERRS);
ERROR_OVERFLOW_RO(pcie_ue, PCIE_UE_ERRS);
ERROR_OVERFLOW_RO(other_ce, OTHER_CE_ERRS);
ERROR_OVERFLOW_RO(other_ue, OTHER_UE_ERRS);

#define ERROR_RO(_error, _index) \
	static ssize_t error_##_error##_show(struct device *dev,            \
					     struct device_attribute *da,   \
					     char *buf)                     \
	{                                                                   \
		return smpro_error_data_read(dev, da, buf, _index);         \
	}                                                                   \
	static DEVICE_ATTR_RO(error_##_error)

ERROR_RO(core_ce, CORE_CE_ERRS);
ERROR_RO(core_ue, CORE_UE_ERRS);
ERROR_RO(mem_ce, MEM_CE_ERRS);
ERROR_RO(mem_ue, MEM_UE_ERRS);
ERROR_RO(pcie_ce, PCIE_CE_ERRS);
ERROR_RO(pcie_ue, PCIE_UE_ERRS);
ERROR_RO(other_ce, OTHER_CE_ERRS);
ERROR_RO(other_ue, OTHER_UE_ERRS);

static ssize_t error_smpro_show(struct device *dev, struct device_attribute *da, char *buf)
{
	return smpro_internal_err_read(dev, da, buf, RAS_SMPRO_ERRS);
}
static DEVICE_ATTR_RO(error_smpro);

static ssize_t error_pmpro_show(struct device *dev, struct device_attribute *da, char *buf)
{
	return smpro_internal_err_read(dev, da, buf, RAS_PMPRO_ERRS);
}
static DEVICE_ATTR_RO(error_pmpro);

#define EVENT_RO(_event, _index) \
	static ssize_t event_##_event##_show(struct device *dev,            \
					     struct device_attribute *da,   \
					     char *buf)                     \
	{                                                                   \
		return smpro_event_data_read(dev, da, buf, _index);         \
	}                                                                   \
	static DEVICE_ATTR_RO(event_##_event)

EVENT_RO(vrd_warn_fault, VRD_WARN_FAULT_EVENTS);
EVENT_RO(vrd_hot, VRD_HOT_EVENTS);
EVENT_RO(dimm_hot, DIMM_HOT_EVENTS);

static struct attribute *smpro_errmon_attrs[] = {
	&dev_attr_overflow_core_ce.attr,
	&dev_attr_overflow_core_ue.attr,
	&dev_attr_overflow_mem_ce.attr,
	&dev_attr_overflow_mem_ue.attr,
	&dev_attr_overflow_pcie_ce.attr,
	&dev_attr_overflow_pcie_ue.attr,
	&dev_attr_overflow_other_ce.attr,
	&dev_attr_overflow_other_ue.attr,
	&dev_attr_error_core_ce.attr,
	&dev_attr_error_core_ue.attr,
	&dev_attr_error_mem_ce.attr,
	&dev_attr_error_mem_ue.attr,
	&dev_attr_error_pcie_ce.attr,
	&dev_attr_error_pcie_ue.attr,
	&dev_attr_error_other_ce.attr,
	&dev_attr_error_other_ue.attr,
	&dev_attr_error_smpro.attr,
	&dev_attr_error_pmpro.attr,
	&dev_attr_event_vrd_warn_fault.attr,
	&dev_attr_event_vrd_hot.attr,
	&dev_attr_event_dimm_hot.attr,
	NULL
};

static const struct attribute_group smpro_errmon_attr_group = {
	.attrs = smpro_errmon_attrs
};

static int smpro_errmon_probe(struct platform_device *pdev)
{
	struct smpro_errmon *errmon;
	int ret;

	errmon = devm_kzalloc(&pdev->dev, sizeof(struct smpro_errmon), GFP_KERNEL);
	if (!errmon)
		return -ENOMEM;

	platform_set_drvdata(pdev, errmon);

	errmon->regmap = dev_get_regmap(pdev->dev.parent, NULL);
	if (!errmon->regmap)
		return -ENODEV;

	ret = sysfs_create_group(&pdev->dev.kobj, &smpro_errmon_attr_group);
	if (ret)
		dev_err(&pdev->dev, "SMPro errmon sysfs registration failed\n");

	return 0;
}

static int smpro_errmon_remove(struct platform_device *pdev)
{
	sysfs_remove_group(&pdev->dev.kobj, &smpro_errmon_attr_group);
	pr_info("SMPro errmon sysfs entries removed");

	return 0;
}

static struct platform_driver smpro_errmon_driver = {
	.probe          = smpro_errmon_probe,
	.remove         = smpro_errmon_remove,
	.driver = {
		.name   = "smpro-errmon",
	},
};

module_platform_driver(smpro_errmon_driver);

MODULE_AUTHOR("Tung Nguyen <tung.nguyen@amperecomputing.com>");
MODULE_AUTHOR("Thinh Pham <thinh.pham@amperecomputing.com>");
MODULE_AUTHOR("Hoang Nguyen <hnguyen@amperecomputing.com>");
MODULE_AUTHOR("Thu Nguyen <thu@os.amperecomputing.com>");
MODULE_AUTHOR("Quan Nguyen <quan@os.amperecomputing.com>");
MODULE_DESCRIPTION("Ampere Altra SMpro driver");
MODULE_LICENSE("GPL");
