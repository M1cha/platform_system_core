LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# files that live under /system/etc/...

copy_from := \
	etc/dbus.conf \
	etc/hosts

ifeq ($(TARGET_PRODUCT),full)
copy_from += etc/vold.fstab
endif

ifeq ($(TARGET_PRODUCT),full_x86)
copy_from += etc/vold.fstab
endif

# the /system/etc/init.goldfish.sh is needed to enable emulator support
# in the system image. In theory, we don't need these for -user builds
# which are device-specific. However, these builds require at the moment
# to run the dex pre-optimization *in* the emulator. So keep the file until
# we are capable of running dex preopt on the host.
#
copy_from += etc/init.goldfish.sh

copy_to := $(addprefix $(TARGET_OUT)/,$(copy_from))
copy_from := $(addprefix $(LOCAL_PATH)/,$(copy_from))

$(copy_to) : PRIVATE_MODULE := system_etcdir
$(copy_to) : $(TARGET_OUT)/% : $(LOCAL_PATH)/% | $(ACP)
	$(transform-prebuilt-to-target)

ALL_PREBUILT += $(copy_to)


# files that live under /...

# Only copy init.rc if the target doesn't have its own.
ifneq ($(TARGET_PROVIDES_INIT_RC),true)
file := $(TARGET_ROOT_OUT)/init.rc
$(file) : $(LOCAL_PATH)/init.rc | $(ACP)
	$(transform-prebuilt-to-target)
ifeq ($(TARGET_PRODUCT),iMX53)
	# Partitions are offset a bit by iMX53's special
	# boot partition...
	sed -i -e 's,mmcblk0p5,mmcblk0p6,g;s,mmcblk0p3,mmcblk0p5,g;s,mmcblk0p2,mmcblk0p3,g' $(TARGET_ROOT_OUT)/init.rc
endif
ifeq ($(TARGET_PRODUCT),iMX6)
	# Partitions are offset a bit by iMX6's special
	# boot partition...
	sed -i -e 's,mmcblk0p5,mmcblk0p6,g;s,mmcblk0p3,mmcblk0p5,g;s,mmcblk0p2,mmcblk0p3,g' $(TARGET_ROOT_OUT)/init.rc
endif
ifeq ($(TARGET_PRODUCT),origen)
	# Partitions are offset a bit by Origen's special
	# boot partition...
	sed -i -e 's,mmcblk0p5,mmcblk0p6,g;s,mmcblk0p3,mmcblk0p5,g;s,mmcblk0p2,mmcblk0p3,g' $(TARGET_ROOT_OUT)/init.rc
endif
ifeq ($(TARGET_PRODUCT),snowball)
	# Snowball boots from mmcblk1...
	sed -i -e 's,mmcblk0,mmcblk1,g' $(TARGET_ROOT_OUT)/init.rc
endif
ALL_PREBUILT += $(file)
$(INSTALLED_RAMDISK_TARGET): $(file)
endif

file := $(TARGET_ROOT_OUT)/ueventd.rc
$(file) : $(LOCAL_PATH)/ueventd.rc | $(ACP)
	$(transform-prebuilt-to-target)
ALL_PREBUILT += $(file)
$(INSTALLED_RAMDISK_TARGET): $(file)

# Just like /system/etc/init.goldfish.sh, the /init.godlfish.rc is here
# to allow -user builds to properly run the dex pre-optimization pass in
# the emulator.
file := $(TARGET_ROOT_OUT)/init.goldfish.rc
$(file) : $(LOCAL_PATH)/etc/init.goldfish.rc | $(ACP)
	$(transform-prebuilt-to-target)
ALL_PREBUILT += $(file)
$(INSTALLED_RAMDISK_TARGET): $(file)

file := $(TARGET_ROOT_OUT)/ueventd.goldfish.rc
$(file) : $(LOCAL_PATH)/etc/ueventd.goldfish.rc | $(ACP)
	$(transform-prebuilt-to-target)
ALL_PREBUILT += $(file)
$(INSTALLED_RAMDISK_TARGET): $(file)

# create some directories (some are mount points)
DIRS := $(addprefix $(TARGET_ROOT_OUT)/, \
		sbin \
		dev \
		proc \
		sys \
		system \
		data \
	) \
	$(TARGET_OUT_DATA)

$(DIRS):
	@echo Directory: $@
	@mkdir -p $@

ALL_PREBUILT += $(DIRS)
