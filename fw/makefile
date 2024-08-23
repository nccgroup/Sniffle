SIMPLELINK_SDK_INSTALL_DIR ?= $(HOME)/ti/simplelink_cc13xx_cc26xx_sdk_7_41_00_17

include $(SIMPLELINK_SDK_INSTALL_DIR)/imports.mak

CC = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"
LNK = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-gcc"
OC = "$(GCC_ARMCOMPILER)/bin/arm-none-eabi-objcopy"

NAME = sniffle

CC26X2R1_PLATFORMS = CC2642R1F CC2652R1F
CC1352R1_PLATFORMS = CC1352R1F3
CC2652RB_PLATFORMS = CC2652RB1F CC2652RB1F_1M
CC1352P1_PLATFORMS = CC1352P1F3 CC2652P1F CC1352P1F3_1M CC2652P1F_1M
CC2652R7_PLATFORMS = CC2652R74
CC1352P7_PLATFORMS = CC1352P74 CC2652P74 CC1352P74_1M
CC2651P3_PLATFORMS = CC2651P31
CC1354P10_PLATFORMS = CC1354P106

1M_BAUD_PLATFORMS = CC2652RB1F_1M CC1352P1F3_1M CC2652P1F_1M CC1352P74_1M

SUPPORTED_PLATFORMS = \
    $(CC26X2R1_PLATFORMS) \
    $(CC1352R1_PLATFORMS) \
    $(CC2652RB_PLATFORMS) \
    $(CC1352P1_PLATFORMS) \
    $(CC2652R7_PLATFORMS) \
    $(CC1352P7_PLATFORMS) \
    $(CC2651P3_PLATFORMS) \
    $(CC1354P10_PLATFORMS)

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
    TI_PLAT_NAME = cc13x2_cc26x2
endif
ifneq ($(filter $(PLATFORM), $(CC1352R1_PLATFORMS)),)
    CCXML = ccxml/CC1352R1F3.ccxml
    SYSCFG_BOARD = /ti/boards/CC1352R1_LAUNCHXL
    TI_PLAT_NAME = cc13x2_cc26x2
endif
ifneq ($(filter $(PLATFORM), $(CC2652RB_PLATFORMS)),)
    CCXML = ccxml/CC2652RB1F.ccxml
    SYSCFG_BOARD = /ti/boards/LP_CC2652RB
    TI_PLAT_NAME = cc13x2_cc26x2
endif
ifneq ($(filter $(PLATFORM), $(CC1352P1_PLATFORMS)),)
    CCXML = ccxml/CC1352P1F3.ccxml
    SYSCFG_BOARD = /ti/boards/CC1352P1_LAUNCHXL
    TI_PLAT_NAME = cc13x2_cc26x2
endif
ifneq ($(filter $(PLATFORM), $(CC2652R7_PLATFORMS)),)
    CCXML = ccxml/CC2652R7.ccxml
    SYSCFG_BOARD = /ti/boards/LP_CC2652R7
    TI_PLAT_NAME = cc13x2x7_cc26x2x7
endif
ifneq ($(filter $(PLATFORM), $(CC1352P7_PLATFORMS)),)
    CCXML = ccxml/CC1352P7.ccxml
    SYSCFG_BOARD = /ti/boards/LP_CC1352P7_1
    TI_PLAT_NAME = cc13x2x7_cc26x2x7
endif
ifneq ($(filter $(PLATFORM), $(CC2651P3_PLATFORMS)),)
    CCXML = ccxml/CC2651P3.ccxml
    SYSCFG_BOARD = /ti/boards/LP_CC2651P3
    TI_PLAT_NAME = cc13x1_cc26x1
    HARD_FLOAT = 0
endif
ifneq ($(filter $(PLATFORM), $(CC1354P10_PLATFORMS)),)
    CCXML = ccxml/CC1354P10.ccxml
    SYSCFG_BOARD = /ti/boards/LP_EM_CC1354P10_1
    TI_PLAT_NAME = cc13x4_cc26x4
    HARD_FLOAT = 2
endif

ifneq ($(filter $(PLATFORM), $(1M_BAUD_PLATFORMS)),)
    CFLAGS += -DUART_1M_BAUD
endif

ifeq ($(HARD_FLOAT),2)
    CFLAGS += -mfloat-abi=hard -mfpu=fpv5-sp-d16 -mcpu=cortex-m33
    LFLAGS += -mfloat-abi=hard -mfpu=fpv5-sp-d16 -mcpu=cortex-m33
else ifeq ($(HARD_FLOAT),1)
    CFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16 -mcpu=cortex-m4
    LFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16 -mcpu=cortex-m4
else
    CFLAGS += -mfloat-abi=soft -mcpu=cortex-m4
    LFLAGS += -mfloat-abi=soft -mcpu=cortex-m4
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
SYSCFG_OPT_FILES = $(filter %.opt,$(SYSCFG_FILES))

CFLAGS += -I. \
    -O3 \
    -mthumb \
    -D__STRICT_ANSI__ \
    $(addprefix @,$(SYSCFG_OPT_FILES)) \
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
    -mthumb \
    -nostartfiles \
    -static \
    -Wl,--gc-sections \
    -lgcc \
    -lc \
    -lm \
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
    TXQueue.c \
    measurements.c

OBJECTS = $(patsubst %.c,%.obj,$(SOURCES))

all: $(NAME).hex

.INTERMEDIATE: syscfg
$(SYSCFG_FILES): syscfg
	@ echo Generation complete

syscfg: $(NAME).syscfg
	@ echo Generating configuration files...
	@ $(SYSCFG_CMD_STUB) --output $(@D) $<

%.obj: %.c $(SYSCFG_H_FILES)
	@ echo Building $@
	@ $(CC) $(CFLAGS) $< -c -o $@

$(NAME).out: $(OBJECTS)
	@ echo Linking...
	@ $(LNK) $(OBJECTS) $(LFLAGS) -o $(NAME).out

$(NAME).hex: $(NAME).out
	@echo Generating flash image...
	@ $(OC) -I elf32-little -O ihex $< $@

.PHONY: load clean clean2

clean: clean2
	@ $(RM) $(SYSCFG_GEN_FILES)> $(DEVNULL) 2>&1

# cleans everything except TI SDK and RTOS
clean2:
	@ echo Cleaning...
	@ $(RM) $(OBJECTS) > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).out > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).map > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).hex > $(DEVNULL) 2>&1

load: $(NAME).hex
	@ echo Flashing...
	@ DSLite flash -c $(CCXML) -f -e -r 0 $<
