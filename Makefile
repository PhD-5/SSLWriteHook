THEOS_DEVICE_IP = 192.168.3.227
ARCHS = armv7 arm64
TARGET = iphone:latest:8.0

include theos/makefiles/common.mk

TWEAK_NAME = SSLWriteHook
SSLWriteHook_FILES = Tweak.xm
SSLWriteHook_FRAMEWORKS = UIKit Security

include $(THEOS_MAKE_PATH)/tweak.mk


