SIMPLELINK_SDK_INSTALL_DIR ?= $(HOME)/ti/simplelink_cc13xx_cc26xx_sdk_5_40_00_40

include $(SIMPLELINK_SDK_INSTALL_DIR)/imports.mak

XDCPATH = $(SIMPLELINK_SDK_INSTALL_DIR)/source;$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos/packages;

CC = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"
LNK = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"

CONFIGPKG = rtos_build
NAME = sniffle

CC26X2_PLATFORMS = CC2642R1F CC2652R1F
CC1352_PLATFORMS = CC1352R1F3
CC2652RB_PLATFORMS = CC2652RB1F
CC1352P1_PLATFORMS = CC1352P1F3
SUPPORTED_PLATFORMS = $(CC26X2_PLATFORMS) $(CC1352_PLATFORMS) $(CC2652RB_PLATFORMS) $(CC1352P1_PLATFORMS)

ifeq ($(PLATFORM),)
    PLATFORM = CC2642R1F
endif

ifeq ($(filter $(PLATFORM), $(SUPPORTED_PLATFORMS)),)
    $(error "PLATFORM not in $(SUPPORTED_PLATFORMS)")
endif

ifneq ($(filter $(PLATFORM), $(CC26X2_PLATFORMS)),)
    CCXML = CC26X2/CC2652R1F.ccxml
    SYSCFG_BOARD = /ti/boards/CC26X2R1_LAUNCHXL
endif
ifneq ($(filter $(PLATFORM), $(CC1352_PLATFORMS)),)
    CCXML = CC1352/CC1352R1F3.ccxml
    SYSCFG_BOARD = /ti/boards/CC1352R1_LAUNCHXL
endif
ifneq ($(filter $(PLATFORM), $(CC2652RB_PLATFORMS)),)
    CCXML = CC2652RB/CC2652RB1F.ccxml
    SYSCFG_BOARD = /ti/boards/LP_CC2652RB
endif
ifneq ($(filter $(PLATFORM), $(CC1352P1_PLATFORMS)),)
    CCXML = CC1352P1/CC1352P1F3.ccxml
    SYSCFG_BOARD = /ti/boards/CC1352P1_LAUNCHXL
endif

XDCTARGET = gnu.targets.arm.M4F
TI_PLTFRM = ti.platforms.simplelink:CC13X2_CC26X2
CFLAGS += -DDeviceFamily_CC13X2_CC26X2

CFLAGS += -I. \
    -D__STRICT_ANSI__ \
    "-I$(SIMPLELINK_SDK_INSTALL_DIR)/source/ti/posix/gcc" \
    -std=c99 \
    -ffunction-sections \
    -fdata-sections \
    -gstrict-dwarf \
    -Wall

LFLAGS += \
    -Wl,-T,cc13x2_cc26x2_tirtos.lds \
    "-Wl,-Map,$(NAME).map" \
    "-L$(SIMPLELINK_SDK_INSTALL_DIR)/source" \
    -l:third_party/spiffs/lib/gcc/m4f/spiffs_cc26xx.a \
    "-L$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos/packages" \
    ti_utils_build_linker.cmd.genlibs \
    "-Wl,-T,$(CONFIGPKG)/linker.cmd" \
    -l:ti/devices/cc13x2_cc26x2/driverlib/bin/gcc/driverlib.lib \
    -march=armv7e-m \
    -mthumb \
    -mfloat-abi=hard \
    -mfpu=fpv4-sp-d16 \
    -nostartfiles \
    -static \
    -Wl,--gc-sections \
    "-L$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos/packages/gnu/targets/arm/libs/install-native/arm-none-eabi/lib/thumb/v7e-m/hard" \
    -lgcc \
    -lc \
    -lm \
    -lnosys \
    --specs=nano.specs

# SysConfig generated
SOURCES += ti_drivers_config.c ti_devices_config.c ti_radio_config.c

# Sniffle Code
SOURCES += \
    adv_header_cache.c \
    AuxAdvScheduler.c \
    base64.c \
    CommandTask.c \
    conf_queue.c \
    csa2.c \
    debug.c \
    DelayHopTrigger.c \
    DelayStopTrigger.c \
    main.c \
    messenger.c \
    PacketTask.c \
    RadioTask.c \
    RadioWrapper.c \
    rpa_resolver.c \
    RFQueue.c \
    sw_aes128.c \
    TXQueue.c

OBJECTS = $(patsubst %.c,%.obj,$(SOURCES))

.PRECIOUS: $(CONFIGPKG)/compiler.opt $(CONFIGPKG)/linker.cmd

all: $(NAME).out

$(CONFIGPKG)/compiler.opt: $(CONFIGPKG)/linker.cmd

$(CONFIGPKG)/linker.cmd: sniffle.cfg
	@ echo Running Configuro...
	@ $(XDC_INSTALL_DIR)/xs --xdcpath="$(XDCPATH)" xdc.tools.configuro -c "$(GCC_ARMCOMPILER)" \
        -t $(XDCTARGET) -p $(TI_PLTFRM) --compileOptions "$(CFLAGS)" -o "$(CONFIGPKG)" $<

.INTERMEDIATE: syscfg
ti_radio_config.c ti_drivers_config.c ti_devices_config.c ti_radio_config.h ti_drivers_config.h: syscfg

syscfg: sniffle.syscfg
	@ echo Generating configuration files...
	@ $(SYSCONFIG_TOOL) --board $(SYSCFG_BOARD) --rtos tirtos --compiler gcc --product $(SIMPLELINK_SDK_INSTALL_DIR)/.metadata/product.json --output $(@D) $<

%.obj: %.c $(CONFIGPKG)/compiler.opt syscfg
	@ echo Building $@
	@ $(CC) $(CFLAGS) $< -c @$(CONFIGPKG)/compiler.opt -o $@

$(NAME).out: $(OBJECTS) $(CONFIGPKG)/linker.cmd
	@ echo linking...
	@ $(LNK)  $(OBJECTS) $(LFLAGS) -o $(NAME).out

.PHONY: load clean clean2

clean: clean2
	@ $(RM) -r $(CONFIGPKG) > $(DEVNULL) 2>&1

# cleans everything except TI SDK and RTOS
clean2:
	@ echo Cleaning...
	@ $(RM) $(OBJECTS) > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).out > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).map > $(DEVNULL) 2>&1
	@ $(RM) ti_radio_config.c ti_drivers_config.c ti_devices_config.c ti_radio_config.h ti_drivers_config.h syscfg_c.rov.xs ti_utils_build_linker.cmd.exp ti_utils_build_linker.cmd.genlibs ti_utils_runtime_Makefile ti_utils_runtime_model.gv > $(DEVNULL) 2>&1

load: $(NAME).out
	@ echo Flashing...
	@ DSLite load -f $< -c $(CCXML)
