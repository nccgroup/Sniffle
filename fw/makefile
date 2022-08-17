SIMPLELINK_SDK_INSTALL_DIR ?= $(HOME)/ti/simplelink_cc13xx_cc26xx_sdk_6_20_00_29

include $(SIMPLELINK_SDK_INSTALL_DIR)/imports.mak

CC = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"
LNK = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"

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
    CFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
    LFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
else
    CFLAGS += -mfloat-abi=soft
    LFLAGS += -mfloat-abi=soft
endif

SYSCFG_CMD_STUB = $(SYSCONFIG_TOOL) --compiler gcc --product $(SIMPLELINK_SDK_INSTALL_DIR)/.metadata/product.json
SYSCFG_CMD_STUB += --board $(SYSCFG_BOARD) --rtos tirtos7
SYSCFG_GEN_FILES := $(shell $(SYSCFG_CMD_STUB) --listGeneratedFiles --output . $(NAME).syscfg)
SYSCFG_REF_FILES := $(shell $(SYSCFG_CMD_STUB) --listReferencedFiles --output . $(NAME).syscfg)

ifeq ($(OS),Windows_NT)
	SYSCFG_FILES = $(subst \,/,$(SYSCFG_REF_FILES) $(SYSCFG_GEN_FILES))
else
	SYSCFG_FILES = $(SYSCFG_REF_FILES) $(SYSCFG_GEN_FILES)
endif
SYSCFG_C_FILES = $(filter %.c,$(SYSCFG_FILES))
SYSCFG_H_FILES = $(filter %.h,$(SYSCFG_FILES))

CFLAGS += -I. \
    -O3 \
    -mcpu=cortex-m4 \
    -march=armv7e-m \
    -mthumb \
    -D__STRICT_ANSI__ \
    "-I$(SIMPLELINK_SDK_INSTALL_DIR)/source" \
    "-I$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos7/packages" \
    "-I$(SIMPLELINK_SDK_INSTALL_DIR)/source/ti/posix/gcc" \
    -std=c99 \
    -ffunction-sections \
    -fdata-sections \
    -gstrict-dwarf \
    -Wall \
    "-I$(GCC_ARMCOMPILER)/arm-none-eabi/include/newlib-nano" \
    "-I$(GCC_ARMCOMPILER)/arm-none-eabi/include"

LFLAGS += \
    -Wl,-T,$(TI_PLAT_NAME)_tirtos7.lds \
    "-Wl,-Map,$(NAME).map" \
    "-L$(SIMPLELINK_SDK_INSTALL_DIR)/source" \
    "-L$(SIMPLELINK_SDK_INSTALL_DIR)/kernel/tirtos7/packages" \
    ti_utils_build_linker.cmd.genlibs \
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
SOURCES += $(SYSCFG_C_FILES)

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

all: $(NAME).out

.INTERMEDIATE: syscfg
$(SYSCFG_FILES): syscfg
	@ echo generation complete

syscfg: $(NAME).syscfg
	@ echo Generating configuration files...
	@ $(SYSCFG_CMD_STUB) --output $(@D) $<
ifneq ($(filter $(PLATFORM), $(CC2651P3_PLATFORMS)),)
	@ echo Modifying ti_radio_config.c to remove bAcceptSyncInfo line \(CC2651P3 only\)
	@ sed -i "s/.extFilterConfig.bAcceptSyncInfo = 0x0,*/\/\/.extFilterConfig.bAcceptSyncInfo = 0x0,/g" ti_radio_config.c
endif

%.obj: %.c $(SYSCFG_H_FILES)
	@ echo Building $@
	@ $(CC) $(CFLAGS) $< -c -o $@

$(NAME).out: $(OBJECTS)
	@ echo linking...
	@ $(LNK) $(OBJECTS) $(LFLAGS) -o $(NAME).out

.PHONY: load clean clean2

clean: clean2
	@ $(RM) $(SYSCFG_GEN_FILES)> $(DEVNULL) 2>&1

# cleans everything except TI SDK and RTOS
clean2:
	@ echo Cleaning...
	@ $(RM) $(OBJECTS) > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).out > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).map > $(DEVNULL) 2>&1

load: $(NAME).out
	@ echo Flashing...
	@ DSLite load -f $< -c $(CCXML)
