LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)


LOCAL_SRC_FILES := \
	src/wlan_wapi_sms4c.c \
	src/wlan_wapi_wpi_pcrypt.c \
	src/wlan_wapi_ecc.c \
	src/wlan_wapi_pack.c \
	src/wlan_wapi_unpack.c \
	src/wlan_wapi_x509.c \
	src/wlan_wapi_wapicert.c \
	src/wlan_wapi_waiprocess.c\
	src/os_adaptor.c

LOCAL_MODULE := wapi


LOCAL_C_INCLUDES := $(LOCAL_PATH)/inc

include $(BUILD_STATIC_LIBRARY)
