SIMPLELINK_SDK_INSTALL_DIR ?= $(HOME)/ti/simplelink_cc13xx_cc26xx_sdk_6_10_00_29

include $(SIMPLELINK_SDK_INSTALL_DIR)/imports.mak

XDCPATH = $(SIMPLELINK_SDK_INSTALL_DIR)/source;$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos/packages;

CC = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"
LNK = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"

CONFIGPKG = rtos_build
NAME = sniffle

CC26X2R1_PLATFORMS = CC2642R1F CC2652R1F
CC1352R1_PLATFORMS = CC1352R1F3
CC2652RB_PLATFORMS = CC2652RB1F
CC1352P1_PLATFORMS = CC1352P1F3
CC2652R7_PLATFORMS = CC2652R74
CC1352P7_PLATFORMS = CC1352P74
CC2651P3_PLATFORMS = CC2651P31

SUPPORTED_PLATFORMS = \
    $(CC26X2R1_PLATFORMS) \
    $(CC1352R1_PLATFORMS) \
    $(CC2652RB_PLATFORMS) \
    $(CC1352P1_PLATFORMS) \
    $(CC2652R7_PLATFORMS) \
    $(CC1352P7_PLATFORMS) \
    $(CC2651P3_PLATFORMS)

ifeq ($(PLATFORM),)
    PLATFORM = CC2642R1F
endif

ifeq ($(filter $(PLATFORM), $(SUPPORTED_PLATFORMS)),)
    $(error "PLATFORM not in $(SUPPORTED_PLATFORMS)")
endif

HARD_FLOAT = 1

ifneq ($(filter $(PLATFORM), $(CC26X2R1_PLATFORMS)),)
    CCXML = ccxml/CC2652R1F.ccxml
    SYSCFG_BOARD = /ti/boards/CC26X2R1_LAUNCHXL
    TI_PLTFRM = ti.platforms.simplelink:CC13X2_CC26X2
    TI_PLAT_NAME = cc13x2_cc26x2
    CFLAGS += -DDeviceFamily_CC26X2
endif
ifneq ($(filter $(PLATFORM), $(CC1352R1_PLATFORMS)),)
    CCXML = ccxml/CC1352R1F3.ccxml
    SYSCFG_BOARD = /ti/boards/CC1352R1_LAUNCHXL
    TI_PLTFRM = ti.platforms.simplelink:CC13X2_CC26X2
    TI_PLAT_NAME = cc13x2_cc26x2
    CFLAGS += -DDeviceFamily_CC13X2
endif
ifneq ($(filter $(PLATFORM), $(CC2652RB_PLATFORMS)),)
    CCXML = ccxml/CC2652RB1F.ccxml
    SYSCFG_BOARD = /ti/boards/LP_CC2652RB
    TI_PLTFRM = ti.platforms.simplelink:CC13X2_CC26X2
    TI_PLAT_NAME = cc13x2_cc26x2
    CFLAGS += -DDeviceFamily_CC26X2
endif
ifneq ($(filter $(PLATFORM), $(CC1352P1_PLATFORMS)),)
    CCXML = ccxml/CC1352P1F3.ccxml
    SYSCFG_BOARD = /ti/boards/CC1352P1_LAUNCHXL
    TI_PLTFRM = ti.platforms.simplelink:CC13X2_CC26X2
    TI_PLAT_NAME = cc13x2_cc26x2
    CFLAGS += -DDeviceFamily_CC13X2
endif
ifneq ($(filter $(PLATFORM), $(CC2652R7_PLATFORMS)),)
    CCXML = ccxml/CC2652R7.ccxml
    SYSCFG_BOARD = /ti/boards/LP_CC2652R7
    TI_PLTFRM = ti.platforms.simplelink:CC13X2_CC26X2
    TI_PLAT_NAME = cc13x2x7_cc26x2x7
    CFLAGS += -DDeviceFamily_CC26X2X7
endif
ifneq ($(filter $(PLATFORM), $(CC1352P7_PLATFORMS)),)
    CCXML = ccxml/CC1352P7.ccxml
    SYSCFG_BOARD = /ti/boards/LP_CC1352P7_1
    TI_PLTFRM = ti.platforms.simplelink:CC13X2_CC26X2
    TI_PLAT_NAME = cc13x2x7_cc26x2x7
    CFLAGS += -DDeviceFamily_CC13X2X7
endif
ifneq ($(filter $(PLATFORM), $(CC2651P3_PLATFORMS)),)
    CCXML = ccxml/CC2651P3.ccxml
    SYSCFG_BOARD = /ti/boards/LP_CC2651P3
    TI_PLTFRM = ti.platforms.simplelink:CC13X1_CC26X1
    TI_PLAT_NAME = cc13x1_cc26x1
    CFLAGS += -DDeviceFamily_CC26X1
    HARD_FLOAT = 0
endif

ifeq ($(HARD_FLOAT),1)
    XDCTARGET = gnu.targets.arm.M4F
    LFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
    LFLAGS += "-L$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos/packages/gnu/targets/arm/libs/install-native/arm-none-eabi/lib/thumb/v7e-m/hard"
else
    XDCTARGET = gnu.targets.arm.M4
    LFLAGS += -mfloat-abi=soft
    LFLAGS += "-L$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos/packages/gnu/targets/arm/libs/install-native/arm-none-eabi/lib/thumb/v7e-m/nofp"
endif

CFLAGS += -I. \
    -D__STRICT_ANSI__ \
    "-I$(SIMPLELINK_SDK_INSTALL_DIR)/source/ti/posix/gcc" \
    -std=c99 \
    -ffunction-sections \
    -fdata-sections \
    -gstrict-dwarf \
    -Wall

LFLAGS += \
    -Wl,-T,$(TI_PLAT_NAME)_tirtos.lds \
    "-Wl,-Map,$(NAME).map" \
    "-L$(SIMPLELINK_SDK_INSTALL_DIR)/source" \
    -l:third_party/spiffs/lib/gcc/m4f/spiffs_cc26xx.a \
    "-L$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos/packages" \
    ti_utils_build_linker.cmd.genlibs \
    "-Wl,-T,$(CONFIGPKG)/linker.cmd" \
    -l:ti/devices/$(TI_PLAT_NAME)/driverlib/bin/gcc/driverlib.lib \
    -march=armv7e-m \
    -mthumb \
    -nostartfiles \
    -static \
    -Wl,--gc-sections \
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
ifneq ($(filter $(PLATFORM), $(CC2651P3_PLATFORMS)),)
	@ echo Modifying ti_radio_config.c to remove bAcceptSyncInfo line \(CC2651P3 only\)
	@ sed -i "s/.extFilterConfig.bAcceptSyncInfo = 0x0,*/\/\/.extFilterConfig.bAcceptSyncInfo = 0x0,/g" ti_radio_config.c
endif

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
