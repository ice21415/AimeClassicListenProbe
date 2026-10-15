ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:15.0
include $(THEOS)/makefiles/common.mk
TWEAK_NAME = AimeClassicListenProbe
AimeClassicListenProbe_FILES = Tweak.m
AimeClassicListenProbe_CFLAGS = -fobjc-arc -Wall -Wextra -Werror
AimeClassicListenProbe_FRAMEWORKS = Foundation
include $(THEOS_MAKE_PATH)/tweak.mk
