/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright (C) 2012 Sony Mobile Communications AB.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#include "includes.h"


#include "common.h"
#include <sys/ioctl.h>

#include "wpa.h"
#include "eloop.h"
#include "config.h"
#include "l2_packet.h"
#include "wpa_supplicant_i.h"
#include "ctrl_iface.h"
#include "version.h"
#include "wpa_ctrl.h"

#include "wlan_wapi_iface_os_svc.h"
#include "wlan_wapi_iface.h"

#include "stdlib.h"
#include "stdio.h"
#include "fcntl.h"

#include <signal.h>
#include <time.h>

#include <wpa.h>
#include "ieee802_11_defs.h"

#include <driver.h>
#include <driver_i.h>
#include "bss.h"
#define IW_AUTH_CIPHER_SMS4     0x00000040
#define IW_MODE_AUTO	0
/*STA MAC address*/
extern uint8	g_bSTAMac[WLAN_WAPI_IFACE_MAC_ADDR_LEN];
/*STA MAC address*/
extern uint8	g_bAPBSSIDMac[WLAN_WAPI_IFACE_MAC_ADDR_LEN];

struct wpa_supplicant *g_wpa_s;
wlan_wapi_iface_event_type g_wapi_wlan_event;
wlan_wapi_iface_event_type *g_wlan_event = &g_wapi_wlan_event;

struct wpa_driver_wext_data {
	void *ctx;
	int event_sock;
	int ioctl_sock;
	int mlme_sock;
	char ifname[IFNAMSIZ + 1];
	int ifindex;
	int ifindex2;
	u8 *assoc_req_ies;
	size_t assoc_req_ies_len;
	u8 *assoc_resp_ies;
	size_t assoc_resp_ies_len;
	struct wpa_driver_capa capa;
	int has_capability;
	int we_version_compiled;

	/* for set_auth_alg fallback */
	int use_crypt;
	int auth_alg_fallback;

	int operstate;

	char mlmedev[IFNAMSIZ + 1];

	int scan_complete_events;
};


extern int wpa_parse_wapi_ie(const u8 *wapi_ie, size_t wpai_ie_len,
		     struct wapi_ie_data *data);

extern wlan_wapi_iface_start_ind_cback_type TE_WAPI_ASUE_Init(void);
extern void TE_WAPI_ASUE_Deinit(void);
extern int wapi_driver_wext_ioctrl(
		struct wpa_driver_wext_data *drv, int comand,
		char *buf  ,
		size_t buf_len);

const u8 *wpa_bss_get_ie(const struct wpa_bss *bss, u8 ie);

extern void wlan_wapi_iface_event_cback(wlan_wapi_iface_event_type *wlan_ev,
					void *user_data_ptr);
void wapi_supplicant_event(struct wpa_supplicant *wpa_s,
			enum wpa_event_type event, void *data);

#define  WAPI_IFACE_CMD_SET_KEYS  WLAN_PRIV_SET_WAPI_KEY

struct _WLAN_WAPI_KEY {
	u8	keyType;
	u8	keyDirection;  /*reserved for future use*/
	u8	keyId;
	u8	addrIndex[12]; /*reserved for future use*/
	u32	wpiekLen;
	u8	wpiek[16];
	u32	wpickLen;
	u8	wpick[16];
	u8	pn[16];        /*reserved for future use*/
} STRUCT_PACKED;

typedef struct _WLAN_WAPI_KEY WLAN_WAPI_KEY;

typedef struct _WAPI_BKID {
	u8	bkid[16];
} WAPI_BKID;

typedef struct _WLAN_BKID_LIST {
	u16	length;
	u16	BKIDCount;
	WAPI_BKID	BKID[1];
} WLAN_BKID_LIST;

#define MAX_NUM_AKM_SUITES	16
#define MAX_NUM_UNI_SUITES	16
#define MAX_NUM_BKIDS	16


struct _WAPI_AssocInfo {
	u8	elementId;
	u8	length;
	u16	version;
	u16	akmSuiteCount;
	u32	akmSuite[MAX_NUM_AKM_SUITES];
	u16	unicastSuiteCount;
	u32	unicastSuite[MAX_NUM_UNI_SUITES];
	u32	multicastSuite;
	u16	wapiCability;
	u16	bkidCount;
	WAPI_BKID	bkidList[MAX_NUM_BKIDS];
} STRUCT_PACKED;

typedef struct _WAPI_AssocInfo WAPI_AssocInfo;
typedef struct _WAPI_AssocInfo *pWAPI_IEAssocInfo;

void wlan_wapi_iface_print(uint32 priority,  const char *format, ...)
{
	wpa_printf2(priority, format);
}

wlan_wapi_iface_return_status_enum_type wlan_wapi_iface_auth_result_ind(
			void *wapi_iface_handle,
			wlan_wapi_iface_auth_result_type   auth_result)
{
	struct wpa_supplicant *wpa_s = g_wpa_s;
	wpa_s->wapi_auth_result = auth_result;

	return WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS;
}


wlan_wapi_iface_return_status_enum_type	 wlan_wapi_iface_status_ind(
			void *wapi_iface_handle,
			wlan_wapi_iface_wai_status_event_enum_type status_ev)
{
	struct wpa_supplicant *wpa_s = g_wpa_s;
	wpa_s->wapi_wai_status = status_ev;
	return WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS;
}


uint64 wlan_wapi_iface_get_sys_time(void)
{
	srand((int)time(NULL));

	return  rand();
}

struct wpa_supplicant *wapi_supplicant_init(struct wpa_supplicant *wpa_s)
{	g_wpa_s = wpa_s;
	for (;;) {
		wpa_s->l2_wapi = l2_packet_init(wpa_s->ifname,
				wpa_drv_get_mac_addr(wpa_s),
				WLAN_WAPI_IFACE,
				wapi_supplicant_rx_eapol,
				wpa_s,
				0);
		wpa_printf(MSG_INFO, "%s: Init WAI packet %s\n", __func__,
		wpa_s->ifname);

		if (wpa_s->l2_wapi)
			break;
		os_sleep(5, 0);
		}
		if (l2_packet_get_own_addr(wpa_s->l2_wapi, wpa_s->own_addr)) {
			fprintf(stderr, "Failed to get own L2 address\n");
			return NULL;
		}
		wpa_printf(MSG_INFO, "Own MAC address: " MACSTR,
		MAC2STR(wpa_s->own_addr));

		TE_WAPI_ASUE_Init();
	return wpa_s;
}

void wapi_supplicant_deinit()
{
	wpa_printf(MSG_DEBUG, "%s: Entry \n", __func__);
	TE_WAPI_ASUE_Deinit();
	g_wpa_s = NULL;
}

void wapi_supplicant_associate(struct wpa_supplicant *wpa_s,
			struct wpa_bss *bss, struct wpa_ssid *ssid)
{
	struct wpa_driver_associate_params params;

	wlan_wapi_iface_connect_event_type *wlan_connect_data =
	&g_wlan_event->event_info.connect_ev;
	wlan_wapi_iface_config_params_type *ap_param =
	&g_wlan_event->event_info.connect_ev.config_params;
	wlan_wapi_iface_passphrase_info_type *pskinfo =
	&g_wlan_event->event_info.connect_ev.config_params.auth_info.psk_info;

	WAPI_AssocInfo  wapi_associnfo ;
	enum wpa_cipher cipher_pairwise, cipher_group;
	size_t len;
	int ret = -1;

	u16 wapi_ie_len = 0;
	u8 *wapi_ie = NULL;

	wpa_supplicant_set_state(wpa_s, WPA_ASSOCIATING);
	memset(ap_param, 0, sizeof(wlan_wapi_iface_config_params_type));
	if (ssid->key_mgmt & WPA_KEY_MGMT_WAPI_PSK) {
		ap_param->auth_type = WLAN_WAPI_IFACE_AUTH_TYPE_PSK;
		if (ssid->wapi_psk == NULL) {
			wpa_printf(MSG_WARNING, "[%s] No WAPI PSK\n", __func__);
			return;
		}
		if (ssid->wapi_key_type == WAPI_KEY_TYPE_HEX) {
			pskinfo->psk_type =
			WLAN_WAPI_IFACE_PSK_PASSPHRASE_TYPE_HEX;
			len = strlen(ssid->wapi_psk);
			pskinfo->psk_val_type.len = PMK_LEN;
			memcpy(&pskinfo->psk_val_type.passphrase,
			ssid->wapi_psk, PMK_LEN);
			wpa_printf(MSG_DEBUG,
			"[%s] WAPI-PSK:HEX KEY:%s PSK Len:%d ",
			 __func__, pskinfo->psk_val_type.passphrase,
			pskinfo->psk_val_type.len);
	} else {
		pskinfo->psk_type = WLAN_WAPI_IFACE_PSK_PASSPHRASE_TYPE_ASCII;
		len = strlen(ssid->wapi_psk);
		pskinfo->psk_val_type.len = len;
		memcpy(&pskinfo->psk_val_type.passphrase, ssid->wapi_psk, len);
		wpa_printf(MSG_DEBUG, "[%s] WAPI-PSK:ASCII KEY:%s PSK Len:%d ",
			 __func__, pskinfo->psk_val_type.passphrase,
			pskinfo->psk_val_type.len);
	}
	} else if (ssid->key_mgmt & WPA_KEY_MGMT_WAPI_CERT) {

		ap_param->auth_type = WLAN_WAPI_IFACE_AUTH_TYPE_CERT;
	        if (ssid->as_cert_uri)
		{

		    len = os_strlen(ssid->as_cert_uri);
		    memcpy(&ap_param->auth_info.as_cert_info.cert_file_uri[0],
			    ssid->as_cert_uri, len);
		    wpa_printf(MSG_DEBUG, "[%s] WAPI-CERT::"
			    "Server CERT SSID uri:%s Len:%d",
			    __func__, ssid->as_cert_uri, len);
		}
		if (ssid->user_cert_uri)
		{

		    len = os_strlen(ssid->user_cert_uri);
		    os_memcpy(&ap_param->auth_info.user_cert_info.cert_file_uri[0],
			ssid->user_cert_uri, len);
		    wpa_printf(MSG_DEBUG, "[%s] WAPI-CERT:"
			    "User CERT SSID uri:%s Len:%d",
			    __func__, ssid->user_cert_uri, len);
		}
		if (ssid->user_key_uri)
		{
		    len = os_strlen(ssid->user_key_uri);
		    os_memcpy(&ap_param->auth_info.user_key_cert_info.cert_file_uri[0],
			ssid->user_key_uri, len);
		    wpa_printf(MSG_DEBUG, "[%s] WAPI-CERT:"
			    "User key CERT SSID uri:%s Len:%d",
			    __func__, ssid->user_key_uri, len);
		}
	} else {
		ap_param->auth_type = WLAN_WAPI_IFACE_AUTH_TYPE_OPEN;
		wpa_printf(MSG_INFO, "[%s] WAPI: OPEN AUTH", __func__);
	}

	cipher_pairwise = CIPHER_SMS4;
	cipher_group = CIPHER_SMS4;
	wpa_hexdump_ascii(MSG_DEBUG, " curent ssid:", (u8 *)ssid->ssid,
			ssid->ssid_len);
	memset(&params, 0, sizeof(params));
	if (bss) {
		const u8 *ie = wpa_bss_get_ie(bss, WLAN_EID_SSID);
		if (ie) {
			params.ssid = ie + 2;
			params.ssid_len = ie[1];
		}
		params.bssid = bss->bssid;
		wapi_ie = wpa_bss_get_ie(bss, WLAN_EID_WAPI);
		wapi_ie_len = wapi_ie ? wapi_ie[1] + 2 : 0;
	} else {
		params.ssid = ssid->ssid;
		params.ssid_len = ssid->ssid_len;
	}
	params.mode = IW_MODE_AUTO;
	wpa_s->ap_wapi_ie_len = wapi_ie_len;
	if (wapi_ie_len) {
		memcpy(wpa_s->ap_wapi_ie, wapi_ie, wapi_ie_len);
	}

	wpa_s->assoc_wapi_ie_len = wapi_ie_len;
	if (wapi_ie_len)
		memcpy(wpa_s->assoc_wapi_ie, wapi_ie, wapi_ie_len);

	wpa_printf(MSG_DEBUG, "[%s] WAPI ASSOC INFO:: WAPI IE Len:%d ",
			 __func__,  wapi_ie_len);

	memset(&wapi_associnfo, 0, sizeof(wapi_associnfo));
	if (wapi_ie_len) {
		struct wapi_ie_data data;
		memset(&data, 0, sizeof(struct wapi_ie_data));
		wpa_parse_wapi_ie(wpa_s->assoc_wapi_ie,
			wpa_s->assoc_wapi_ie_len, &data);

		memset(&wapi_associnfo, 0, sizeof(wapi_associnfo));

		wapi_associnfo.elementId = data.elem_id;
		wapi_associnfo.length =  data.len;
		wapi_associnfo.version = data.version;
		wapi_associnfo.akmSuiteCount = data.akmnumber;
		memcpy(wapi_associnfo.akmSuite, data.akmlist, (4*data.akmnumber));
		wapi_associnfo.unicastSuiteCount = data.singlecodenumber;
		memcpy(wapi_associnfo.unicastSuite, data.singlecodelist,
					(4*data.singlecodenumber));
		wapi_associnfo.multicastSuite = data.multicode;
		wapi_associnfo.wapiCability = data.wapiability;
		wapi_associnfo.bkidCount = data.bkidnumber;
		memcpy(wapi_associnfo.bkidList, data.bkidlist,
				(data.bkidnumber)*sizeof(WAPI_BKID));
	}
	params.wpa_ie_len = wpa_s->assoc_wapi_ie_len;
	params.wpa_ie = wpa_s->assoc_wapi_ie;
	if (bss)
		params.freq = bss->freq;
	params.pairwise_suite = cipher_pairwise;
	params.group_suite = cipher_group;
	params.key_mgmt_suite = wpa_s->key_mgmt;
	params.auth_alg = WPA_AUTH_ALG_OPEN;
	wpa_printf(MSG_DEBUG, "%s: wpa_s->key_mgmt %d, ssid->key_mgmt %d \n",
			 __func__, wpa_s->key_mgmt, ssid->key_mgmt);

	wpa_printf(MSG_DEBUG, "[%s] SETTING WAPI MODE DONE ", __func__);

	wpa_printf(MSG_INFO, "[%s] SETTING WAPI MODE & ASSOC INFO DONE ",
			 __func__);

	if (!memcmp(wpa_s->bssid, "\x00\x00\x00\x00\x00\x00", ETH_ALEN)) {
		/* Timeout for IEEE 802.11 authentication and association */
		wpa_supplicant_req_auth_timeout(wpa_s, 10, 0);
		wpa_hexdump(MSG_DEBUG, "wapi IE: ", params.wpa_ie,
			params.wpa_ie_len);
		if (wpa_drv_associate(wpa_s, &params)) {
			wpa_printf(MSG_ERROR,
			"wapi_supplicant_associate failed");
			wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);
		}
	}

}

void wapi_supplicant_disassociate(struct wpa_supplicant *wpa_s,
				int reason_code)
{
	wpa_printf(MSG_INFO, "%s: In\n", __func__);

	wapi_supplicant_event(wpa_s, EVENT_DISASSOC, &reason_code);
}


void wapi_supplicant_event(struct wpa_supplicant *wpa_s,
			 enum wpa_event_type event, void *data)
{
	u8 bssid[ETH_ALEN];

	wpa_printf(MSG_DEBUG, "%s: event = %d\n", __func__, event);
	switch (event) {
	case EVENT_ASSOC:
	{
		wlan_wapi_iface_connect_event_type *wlan_connect_data =
			&g_wlan_event->event_info.connect_ev;
		wlan_wapi_iface_config_params_type *ap_param =
			&g_wlan_event->event_info.connect_ev.config_params;
		wlan_wapi_iface_passphrase_info_type *pskinfo =
			&g_wlan_event->event_info.connect_ev.config_params.auth_info.psk_info;
		size_t len;

		wpa_drv_get_bssid(wpa_s, bssid);
		wpa_hexdump(MSG_DEBUG, "bssid", bssid, sizeof(bssid));
		memcpy(wlan_connect_data->bssid , bssid, ETH_ALEN);
		memcpy(wlan_connect_data->sta_mac_address,
			wpa_s->own_addr, ETH_ALEN);
		memcpy(wlan_connect_data->beacon_probe_wapi_ie.ie_data,
			wpa_s->ap_wapi_ie, wpa_s->ap_wapi_ie_len);
		wlan_connect_data->beacon_probe_wapi_ie.ie_len =
		wpa_s->ap_wapi_ie_len;
		wpa_printf(MSG_DEBUG, "%s:Beacon probe WAPI IE LEN = %02d %02d",
			 __func__, wpa_s->ap_wapi_ie_len,
			wlan_connect_data->beacon_probe_wapi_ie.ie_len);
		if (wpa_s->current_ssid->key_mgmt & WPA_KEY_MGMT_WAPI_PSK) {
			ap_param->auth_type = WLAN_WAPI_IFACE_AUTH_TYPE_PSK;
			if (wpa_s->current_ssid->wapi_psk == NULL) {
				wpa_printf(MSG_ERROR, "[%s] No WAPI PSK\n",
					 __func__);
				return;
			}
		if (wpa_s->current_ssid->wapi_key_type == WAPI_KEY_TYPE_HEX) {
			pskinfo->psk_type =
				WLAN_WAPI_IFACE_PSK_PASSPHRASE_TYPE_HEX;
			len = strlen(wpa_s->current_ssid->wapi_psk);
			pskinfo->psk_val_type.len = PMK_LEN;
			memcpy(&pskinfo->psk_val_type.passphrase,
				wpa_s->current_ssid->wapi_psk, PMK_LEN);
			wpa_printf(MSG_INFO, "%s: WAPI-PSK: HEX KEY:%s "
				"PSK Len:%d ",
				__func__, pskinfo->psk_val_type.passphrase,
				pskinfo->psk_val_type.len);
		} else {
			pskinfo->psk_type =
				WLAN_WAPI_IFACE_PSK_PASSPHRASE_TYPE_ASCII;
			len = strlen(wpa_s->current_ssid->wapi_psk);
			pskinfo->psk_val_type.len = len;
			memcpy(&pskinfo->psk_val_type.passphrase,
				wpa_s->current_ssid->wapi_psk, len);
			wpa_printf(MSG_INFO, "%s: WAPI-PSK:"
				" ASCII KEY:%s PSK Len:%d ",
				__func__, pskinfo->psk_val_type.passphrase,
				pskinfo->psk_val_type.len);
			}
		} else if (wpa_s->current_ssid->key_mgmt &
				WPA_KEY_MGMT_WAPI_CERT) {
			ap_param->auth_type = WLAN_WAPI_IFACE_AUTH_TYPE_CERT;
			if (wpa_s->current_ssid->as_cert_uri)
			{
			    len = os_strlen(wpa_s->current_ssid->as_cert_uri);
			    os_memcpy(&ap_param->auth_info.as_cert_info.cert_file_uri,
				    wpa_s->current_ssid->as_cert_uri, len);
			    wpa_printf(MSG_INFO, "[%s] WAPI-CERT:"
				    "Server CERT Current SSID uri:%s Len:%d",
				    __func__, wpa_s->current_ssid->as_cert_uri, len);
			}
			if (wpa_s->current_ssid->user_cert_uri)
			{
			    len = os_strlen(wpa_s->current_ssid->user_cert_uri);
			    os_memcpy(&ap_param->auth_info.user_cert_info.cert_file_uri,
				    wpa_s->current_ssid->user_cert_uri, len);
			    wpa_printf(MSG_INFO, "[%s] WAPI-CERT"
				    ":User CERT current SSID uri:%s Len:%d",
				    __func__, wpa_s->current_ssid->user_cert_uri, len);
			}
			if (wpa_s->current_ssid->user_key_uri)
			{
			    len = os_strlen(wpa_s->current_ssid->user_key_uri);
			    os_memcpy(&ap_param->auth_info.user_key_cert_info.cert_file_uri[0],
				wpa_s->current_ssid->user_key_uri, len);
			    wpa_printf(MSG_DEBUG, "[%s] WAPI-CERT:"
				    "User key CERT SSID uri:%s Len:%d",
				    __func__, wpa_s->current_ssid->user_key_uri, len);
			}
		} else {
			ap_param->auth_type = WLAN_WAPI_IFACE_AUTH_TYPE_OPEN;
		}
		g_wlan_event->event_id = WLAN_WAPI_IFACE_EV_CONNECT;
		wlan_wapi_iface_event_cback(g_wlan_event, NULL);

		break;
	}
	case EVENT_DISASSOC:
		wpa_printf(MSG_INFO, "Disconnect event ");
		g_wlan_event->event_id = WLAN_WAPI_IFACE_EV_DISCONNECT;
		wlan_wapi_iface_event_cback(g_wlan_event, NULL);

		break;
	default:
		wpa_printf(MSG_INFO, "Unknown event %d", event);
		break;
	}
}


wlan_wapi_iface_return_status_enum_type	wlan_wapi_iface_send_pkt(
	void *wapi_iface_handle,
	uint16 etherType,
	uint8 *dst_mac_addr,
	uint32 len,
	uint8 *pkt)
{
	struct wpa_supplicant *wpa_s = g_wpa_s;
	int ret;
	ret = l2_packet_send(wpa_s->l2_wapi,
			dst_mac_addr,
			WLAN_WAPI_IFACE,
			(uint8 *)pkt, (uint32)len);
	if (ret < 0)
		return WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE;
	else
		return WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS;
}

/*Report wapi state to wpasupplicant*/
void wapi_supplicant_key_negotiation_state_report(enum wpa_states state)
{
	struct wpa_supplicant *wpa_s = g_wpa_s;

	if (wpa_s != NULL) {
		wpa_supplicant_set_state(wpa_s, state);
		if (state == WPA_COMPLETED) {
			wpa_supplicant_cancel_auth_timeout(wpa_s);
		}
	}
}

// Get wapi state to wpasupplicant
enum wpa_states wapi_supplicant_get_state()
{
	struct wpa_supplicant *wpa_s = g_wpa_s;
	if (wpa_s != NULL) {
		return wpa_s->wpa_state;
	}
	return 0;
}

timer_t wlan_wapi_iface_create_timer(wlan_wapi_iface_timer_cb_type
			timer_f_ptr, uint32 arg)
{
	timer_t   tid;
	struct  sigevent   se;
	memset(&se, 0, sizeof(se));
	se.sigev_notify = SIGEV_THREAD;
	se.sigev_notify_function = (void *)timer_f_ptr;
	se.sigev_value.sival_int = arg;
	timer_create(CLOCK_REALTIME, &se, &tid);
	return tid;
}

wlan_wapi_iface_timer_cnt_type wlan_wapi_iface_start_timer(timer_t tid,
			 wlan_wapi_iface_timer_cnt_type msecs)
{
	struct   itimerspec   ts,   ots, curr_value;
	wlan_wapi_iface_timer_cnt_type  timevalue;
	wpa_printf(MSG_ERROR, "[%s] IN tid =%d timeout=%d", __func__,
		tid, msecs);

	ts.it_value.tv_sec = 0;
	ts.it_value.tv_nsec = msecs * 1000 * 1000;
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = msecs * 1000 * 1000;
	timer_settime(tid, TIMER_ABSTIME, &ts, &ots);
	timer_gettime(tid, &curr_value);
	timevalue = curr_value.it_value.tv_sec * 1000 +
		curr_value.it_value.tv_nsec % 100000;
	return 0;
}

void wlan_wapi_iface_delete_timer(timer_t tid)
{
	wpa_printf(MSG_ERROR, "[%s] IN tid=%d ", __func__, tid);
	timer_delete(tid);
}

wlan_wapi_iface_timer_cnt_type wlan_wapi_iface_stop_timer(timer_t tid)
{
	struct   itimerspec   ts, ots, curr_value;
	wlan_wapi_iface_timer_cnt_type  timevalue;
	wpa_printf(MSG_ERROR, "[%s] IN  tid=%d", __func__, tid);
	ts.it_value.tv_sec = 0;
	ts.it_value.tv_nsec = 0;
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;
	timer_settime(tid, TIMER_ABSTIME, &ts, &ots);

	timer_gettime(tid,  &curr_value);
	timevalue = curr_value.it_value.tv_sec * 1000 +
		curr_value.it_value.tv_nsec % 100000;

	return timevalue;
}

wlan_wapi_iface_timer_cnt_type wlan_wapi_iface_get_timer(timer_t tid)
{
	struct   itimerspec   ts, ots, curr_value;
	wlan_wapi_iface_timer_cnt_type  timevalue;
	timer_gettime(tid, &curr_value);
	timevalue = curr_value.it_value.tv_sec * 1000 +
		curr_value.it_value.tv_nsec % 100000;

 return timevalue;
}

void *wlan_wapi_iface_get_handle(void)
{
	struct wpa_supplicant *wpa_s = g_wpa_s;
	return (void *)wpa_s->drv_priv;
}

wlan_wapi_iface_return_status_enum_type DriverAPISetWPIKey(
		WLAN_WAPI_KEY *pWpikey)
{
	int ret = 0;
	wpa_printf(MSG_INFO, "%s CMD SET: WAPI KEY SIZE:%d",
		__func__, sizeof(WLAN_WAPI_KEY));

	return WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS ;
}

wlan_wapi_iface_return_status_enum_type wlan_wapi_iface_ioctl(
	void *wapi_iface_handle, wlan_wapi_iface_cmd_type *wapi_cmd)
{
	wlan_wapi_iface_set_key_descriptor_type wapisetkey;
	WLAN_WAPI_KEY wapikey;
	int KeyLength;
	int m = 0 ;

	switch (wapi_cmd->cmd_id)
	{
	case WLAN_WAPI_IFACE_CMD_SET_KEYS:
		wapisetkey =
			wapi_cmd->cmd_info.set_keys_cmd.Keys[wapi_cmd->cmd_info.set_keys_cmd.keyListNum];
		wpa_printf(MSG_INFO, "%s CMD SET: WAPI KEY SIZE:%d",
			__func__, sizeof(wapikey));
		memset(&wapikey, 0, sizeof(wapikey));

		wapikey.keyType = wapisetkey.keyType;
		wapikey.keyId = wapisetkey.keyIndex;
		wapikey.keyDirection = 0;
		memcpy(wapikey.addrIndex, wapisetkey.peerMacAddress, ETH_ALEN);
		memcpy(&wapikey.addrIndex[6], g_bSTAMac, ETH_ALEN);

		wapikey.wpiekLen = 16;
		memcpy(wapikey.wpiek, wapisetkey.key, wapikey.wpiekLen);
		wapikey.wpickLen = 16;
		memcpy(wapikey.wpick, &wapisetkey.key[16], wapikey.wpickLen);
		KeyLength = (wapikey.wpiekLen)+(wapikey.wpickLen);
		wpa_printf(MSG_INFO, "%s CMD SET: WAPI KEY Type:%d Key ID:%d",
			__func__,wapisetkey.keyType,wapisetkey.keyIndex);
		wpa_printf(MSG_INFO, "%s CMD SET: WAPI KEY Leng:%d",__func__,wapisetkey.keyLen);

		for (m = 0 ; m < wapisetkey.keyLen; m++)
			wpa_printf(MSG_INFO, "%s CMD SET: WAPI KEY Data[%d]:%02x ",__func__,m,wapisetkey.key[m]);
		if (wpa_drv_set_key(g_wpa_s, WPA_ALG_SMS4,
				wapisetkey.peerMacAddress,
				wapisetkey.keyIndex, 0, wapikey.pn,
				16, wapisetkey.key, KeyLength)){
			wpa_printf(MSG_DEBUG,
				"Failed to set wapikey to the driver");
		}
	break;

	default:
		break;
	}

	return WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS ;
}

wlan_wapi_iface_return_status_enum_type wlan_wapi_iface_release_handle(
						void *wapi_iface_handle)
{
	return WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS;
}

void* wlan_wapi_iface_fopen(const char *file,  uint32 flag)
{
	FILE *f;
	char *buf;
	f = fopen(file, "rb");
	if (f == NULL)
		return FL_NULL;
	return f;
}

int32 wlan_wapi_iface_fclose(void *fd)
{
	int rs = 0;
	rs = fclose((FILE *)fd);
	if (rs == 0)
		return  0;
	return -1;
}

int32 wlan_wapi_iface_fread(void *fd,  void *buf,  uint32 nbytes)
{
	return fread(buf, sizeof(char), nbytes, (FILE *)fd);
}

int32 wlan_wapi_iface_fwrite(void *fd,  const void *buf,  uint32 nbytes)
{
	return fwrite(buf, sizeof(char), nbytes, (FILE *)fd);
}

int32 wlan_wapi_iface_fseek(void *fd,  int32 offset,  int32 whence)
{
	switch (whence)
	{
	case WLAN_WAPI_IFACE_SEEK_SET:
		fseek((FILE *)fd, offset, SEEK_SET);
		return ftell((FILE *)fd);
	case WLAN_WAPI_IFACE_SEEK_CUR:
		fseek((FILE *)fd, offset, SEEK_CUR);
		return ftell((FILE *)fd);
	case WLAN_WAPI_IFACE_SEEK_END:
		fseek((FILE *)fd, offset, SEEK_END);
		return ftell((FILE *)fd);
	default:
		return 0;
		break;
	}
}
