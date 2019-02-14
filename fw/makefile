SIMPLELINK_CC26X2_SDK_INSTALL_DIR ?= $(HOME)/ti/simplelink_cc13x2_26x2_sdk_2_40_00_81

include $(SIMPLELINK_CC26X2_SDK_INSTALL_DIR)/imports.mak

XDCPATH = $(SIMPLELINK_CC26X2_SDK_INSTALL_DIR)/source;$(SIMPLELINK_CC26X2_SDK_INSTALL_DIR)/kernel/tirtos/packages;

CC = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"
LNK = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"

SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %.c,%.obj,$(SOURCES))

CONFIGPKG = rtos_build
NAME = sniffle

XDCTARGET = gnu.targets.arm.M4F
PLATFORM = ti.platforms.simplelink:CC2642R1F

CFLAGS = -I. \
    -D__STRICT_ANSI__ \
    -DDeviceFamily_CC26X2 \
    "-I$(SIMPLELINK_CC26X2_SDK_INSTALL_DIR)/source/ti/posix/gcc" \
    -std=c99 \
    -ffunction-sections \
    -fdata-sections \
    -gstrict-dwarf \
    -Wall

LFLAGS = -Wl,-T,CC26X2R1_LAUNCHXL_TIRTOS.lds \
    "-Wl,-Map,$(NAME).map" \
    "-L$(SIMPLELINK_CC26X2_SDK_INSTALL_DIR)/source" \
    -l:ti/display/lib/display.am4fg \
    -l:ti/grlib/lib/gcc/m4f/grlib.a \
    -l:third_party/spiffs/lib/gcc/m4f/spiffs_cc26xx.a \
    -l:ti/drivers/rf/lib/rf_multiMode_cc26x2.am4fg \
    -l:ti/drivers/lib/drivers_cc26x2.am4fg \
    "-L$(SIMPLELINK_CC26X2_SDK_INSTALL_DIR)/kernel/tirtos/packages" \
    -l:ti/dpl/lib/dpl_cc26x2.am4fg \
    "-Wl,-T,$(CONFIGPKG)/linker.cmd" \
    -l:ti/devices/cc13x2_cc26x2/driverlib/bin/gcc/driverlib.lib \
    -march=armv7e-m \
    -mthumb \
    -mfloat-abi=hard \
    -mfpu=fpv4-sp-d16 \
    -nostartfiles \
    -static \
    -Wl,--gc-sections \
    "-L$(SIMPLELINK_CC26X2_SDK_INSTALL_DIR)/kernel/tirtos/packages/gnu/targets/arm/libs/install-native/arm-none-eabi/lib/thumb/v7e-m/fpv4-sp/hard" \
    "-L$(GCC_ARMCOMPILER)/arm-none-eabi/lib" \
    -lgcc \
    -lc \
    -lm \
    -lnosys \
    --specs=nano.specs

.PRECIOUS: $(CONFIGPKG)/compiler.opt $(CONFIGPKG)/linker.cmd

all: $(NAME).out

$(CONFIGPKG)/compiler.opt: $(CONFIGPKG)/linker.cmd

$(CONFIGPKG)/linker.cmd: sniffle.cfg
	@ echo Running Configuro...
	@ $(XDC_INSTALL_DIR)/xs --xdcpath="$(XDCPATH)" xdc.tools.configuro -c "$(GCC_ARMCOMPILER)" -t $(XDCTARGET) -p $(PLATFORM) --compileOptions "$(CFLAGS)" -o "$(CONFIGPKG)" $<

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
	@ DSLite load -f $< -c CC2652R1F.ccxml
