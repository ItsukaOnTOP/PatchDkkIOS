ARCHS = arm64
TARGET = iphone:clang:latest:14.0
THEOS_DEVICE_IP = 0.0.0.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = IshinRedirect
IshinRedirect_FILES = Tweak.x
IshinRedirect_CFLAGS = -fobjc-arc
IshinRedirect_FRAMEWORKS = Foundation CFNetwork
IshinRedirect_PRIVATE_FRAMEWORKS = CFNetwork
IshinRedirect_LIBRARIES = substrate

include $(THEOS)/makefiles/tweak.mk
