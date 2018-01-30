#
# Copyright (C) 2010 The Android Open Source Project
# Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.
#

# Include this makefile to generate your hardware specific wpa_supplicant.conf
# Requires: WIFI_DRIVER_SOCKET_IFACE

LOCAL_PATH := $(call my-dir)

########################
include $(CLEAR_VARS)

LOCAL_MODULE := wpa_supplicant.conf
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/wifi

include $(BUILD_SYSTEM)/base_rules.mk

WPA_SUPPLICANT_CONF_TEMPLATE := $(LOCAL_PATH)/wpa_supplicant_template.conf
WPA_SUPPLICANT_CONF_SCRIPT := $(LOCAL_PATH)/wpa_supplicant_conf.sh
$(LOCAL_BUILT_MODULE): PRIVATE_WIFI_DRIVER_SOCKET_IFACE := $(WIFI_DRIVER_SOCKET_IFACE)
$(LOCAL_BUILT_MODULE): PRIVATE_WPA_SUPPLICANT_CONF_TEMPLATE := $(WPA_SUPPLICANT_CONF_TEMPLATE)
$(LOCAL_BUILT_MODULE): PRIVATE_WPA_SUPPLICANT_CONF_SCRIPT := $(WPA_SUPPLICANT_CONF_SCRIPT)
$(LOCAL_BUILT_MODULE) : $(WPA_SUPPLICANT_CONF_TEMPLATE) $(WPA_SUPPLICANT_CONF_SCRIPT)
	@echo Target wpa_supplicant.conf: $@
	@mkdir -p $(dir $@)
	$(hide) WIFI_DRIVER_SOCKET_IFACE="$(PRIVATE_WIFI_DRIVER_SOCKET_IFACE)" \
		bash $(PRIVATE_WPA_SUPPLICANT_CONF_SCRIPT) $(PRIVATE_WPA_SUPPLICANT_CONF_TEMPLATE) > $@

########################
#CONN-EC-WIFI-P2P_CONFIG-01+[
#p2p_supplicant.conf is the same as wpa_supplicant.conf. We need this file to
#avoid customized WIFI AP in wpa_supplicant.conf copying to p2p_supplicant.conf
include $(CLEAR_VARS)

LOCAL_MODULE := p2p_supplicant.conf
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/wifi

include $(BUILD_SYSTEM)/base_rules.mk

WPA_SUPPLICANT_CONF_TEMPLATE := $(LOCAL_PATH)/wpa_supplicant_template.conf
WPA_SUPPLICANT_CONF_SCRIPT := $(LOCAL_PATH)/wpa_supplicant_conf.sh
$(LOCAL_BUILT_MODULE): PRIVATE_WIFI_DRIVER_SOCKET_IFACE := $(WIFI_DRIVER_SOCKET_IFACE)
$(LOCAL_BUILT_MODULE): PRIVATE_WPA_SUPPLICANT_CONF_TEMPLATE := $(WPA_SUPPLICANT_CONF_TEMPLATE)
$(LOCAL_BUILT_MODULE): PRIVATE_WPA_SUPPLICANT_CONF_SCRIPT := $(WPA_SUPPLICANT_CONF_SCRIPT)
$(LOCAL_BUILT_MODULE) : $(WPA_SUPPLICANT_CONF_TEMPLATE) $(WPA_SUPPLICANT_CONF_SCRIPT)
	@echo Target wpa_supplicant.conf: $@
	@mkdir -p $(dir $@)
	$(hide) WIFI_DRIVER_SOCKET_IFACE="$(PRIVATE_WIFI_DRIVER_SOCKET_IFACE)" \
		bash $(PRIVATE_WPA_SUPPLICANT_CONF_SCRIPT) $(PRIVATE_WPA_SUPPLICANT_CONF_TEMPLATE) > $@

#CONN-EC-WIFI-P2P_CONFIG-01+]
########################
