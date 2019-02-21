SIMPLELINK_SDK_INSTALL_DIR ?= $(HOME)/ti/simplelink_cc13x2_26x2_sdk_2_40_00_81

include $(SIMPLELINK_SDK_INSTALL_DIR)/imports.mak

XDCPATH = $(SIMPLELINK_SDK_INSTALL_DIR)/source;$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos/packages;

CC = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"
LNK = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"

CONFIGPKG = rtos_build
NAME = sniffle

CC26X2_PLATFORMS = CC2642R1F CC2652R1F
CC1352_PLATFORMS = CC1352R1F3
SUPPORTED_PLATFORMS = $(CC26X2_PLATFORMS) $(CC1352_PLATFORMS)

ifeq ($(PLATFORM),)
    PLATFORM = CC2642R1F
endif

ifeq ($(filter $(PLATFORM), $(SUPPORTED_PLATFORMS)),)
    $(error "PLATFORM not in $(SUPPORTED_PLATFORMS)")
endif

ifneq ($(filter $(PLATFORM), $(CC26X2_PLATFORMS)),)
    SOURCES = $(wildcard CC26X2/*.c)
    CCXML = CC26X2/CC2652R1F.ccxml
    CFLAGS += -DDeviceFamily_CC26X2
    CFLAGS += -ICC26X2
    LFLAGS += -Wl,-T,CC26X2/CC26X2R1_LAUNCHXL_TIRTOS.lds
    LFLAGS += -l:ti/drivers/rf/lib/rf_multiMode_cc26x2.am4fg
    LFLAGS += -l:ti/drivers/lib/drivers_cc26x2.am4fg
    LFLAGS += -l:ti/dpl/lib/dpl_cc26x2.am4fg
endif
ifneq ($(filter $(PLATFORM), $(CC1352_PLATFORMS)),)
    SOURCES = $(wildcard CC1352/*.c)
    CCXML = CC1352/CC1352R1F3.ccxml
    CFLAGS += -DDeviceFamily_CC13X2
    CFLAGS += -ICC1352
    LFLAGS += -Wl,-T,CC1352/CC1352R1_LAUNCHXL_TIRTOS.lds
    LFLAGS += -l:ti/drivers/rf/lib/rf_multiMode_cc13x2.am4fg
    LFLAGS += -l:ti/drivers/lib/drivers_cc13x2.am4fg
    LFLAGS += -l:ti/dpl/lib/dpl_cc13x2.am4fg
endif


XDCTARGET = gnu.targets.arm.M4F
TI_PLTFRM = ti.platforms.simplelink:$(PLATFORM)

CFLAGS += -I. \
    -D__STRICT_ANSI__ \
    "-I$(SIMPLELINK_SDK_INSTALL_DIR)/source/ti/posix/gcc" \
    -std=c99 \
    -ffunction-sections \
    -fdata-sections \
    -gstrict-dwarf \
    -Wall

LFLAGS += \
    "-Wl,-Map,$(NAME).map" \
    "-L$(SIMPLELINK_SDK_INSTALL_DIR)/source" \
    -l:ti/display/lib/display.am4fg \
    -l:ti/grlib/lib/gcc/m4f/grlib.a \
    -l:third_party/spiffs/lib/gcc/m4f/spiffs_cc26xx.a \
    "-L$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos/packages" \
    "-Wl,-T,$(CONFIGPKG)/linker.cmd" \
    -l:ti/devices/cc13x2_cc26x2/driverlib/bin/gcc/driverlib.lib \
    -march=armv7e-m \
    -mthumb \
    -mfloat-abi=hard \
    -mfpu=fpv4-sp-d16 \
    -nostartfiles \
    -static \
    -Wl,--gc-sections \
    "-L$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos/packages/gnu/targets/arm/libs/install-native/arm-none-eabi/lib/thumb/v7e-m/fpv4-sp/hard" \
    "-L$(GCC_ARMCOMPILER)/arm-none-eabi/lib" \
    -lgcc \
    -lc \
    -lm \
    -lnosys \
    --specs=nano.specs

SOURCES += $(wildcard *.c)
OBJECTS = $(patsubst %.c,%.obj,$(SOURCES))

.PRECIOUS: $(CONFIGPKG)/compiler.opt $(CONFIGPKG)/linker.cmd

all: $(NAME).out

$(CONFIGPKG)/compiler.opt: $(CONFIGPKG)/linker.cmd

$(CONFIGPKG)/linker.cmd: sniffle.cfg
	@ echo Running Configuro...
	@ $(XDC_INSTALL_DIR)/xs --xdcpath="$(XDCPATH)" xdc.tools.configuro -c "$(GCC_ARMCOMPILER)" \
        -t $(XDCTARGET) -p $(TI_PLTFRM) --compileOptions "$(CFLAGS)" -o "$(CONFIGPKG)" $<

%.obj: %.c $(CONFIGPKG)/compiler.opt
	@ echo Building $@
	@ $(CC) $(CFLAGS) $< -c @$(CONFIGPKG)/compiler.opt -o $@

$(NAME).out: $(OBJECTS) $(CONFIGPKG)/linker.cmd
	@ echo linking...
	@ $(LNK)  $(OBJECTS) $(LFLAGS) -o $(NAME).out

.PHONY: load clean

clean:
	@ echo Cleaning...
	@ $(RM) $(OBJECTS) > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).out > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).map > $(DEVNULL) 2>&1
	@ $(RM) -r $(CONFIGPKG) > $(DEVNULL) 2>&1

load: $(NAME).out
	@ echo Flashing...
	@ DSLite load -f $< -c $(CCXML)
