ARCHS = arm64
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = IshinRedirect

IshinRedirect_FILES = Redirect.m
IshinRedirect_CFLAGS = -fobjc-arc
IshinRedirect_FRAMEWORKS = Foundation
IshinRedirect_LDFLAGS = -Wl,-install_name,@rpath/IshinRedirect.dylib

include $(THEOS_MAKE_PATH)/library.mk
