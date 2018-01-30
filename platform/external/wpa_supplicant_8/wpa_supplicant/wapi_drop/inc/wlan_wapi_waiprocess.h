/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef __WLAN_WAPI_WAIPROCESS_H_
#define __WLAN_WAPI_WAIPROCESS_H_

/*=============================================================================
WLAN_WAPI_WAIPROCESS.H

DESCRIPTION

EXTERNALIZED FUNCTIONS


=======================================================================*/

/*===========================================================================

			EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ----------------------------------------------------------

===========================================================================*/

#define   WAPI_HEADER_LEN            12

typedef enum {
	ePACKTYPE_WAPI_PROTO_UNKNOWN = 0x00,
	ePACKTYPE_WAPI_PROTO_PREAUTH = 0x01,
	ePACKTYPE_WAPI_PROTO_STAKEY_REQU = 0x02,
	ePACKTYPE_WAPI_PROTO_AUTH_ACTIVE = 0x03,
	ePACKTYPE_WAPI_PROTO_ACCESS_AUTH_REQU = 0x04,
	ePACKTYPE_WAPI_PROTO_ACCESS_AUTH_RESP = 0x05,
	ePACKTYPE_WAPI_PROTO_CER_AUTH_REQU = 0x06,
	ePACKTYPE_WAPI_PROTO_CER_AUTH_RESP = 0x07,

	ePACKTYPE_WAPI_PROTO_SSKEY_NEG_REQU = 0x08,
	ePACKTYPE_WAPI_PROTO_SSKEY_NEG_RESP = 0x09,
	ePACKTYPE_WAPI_PROTO_SSKEY_NEG_ACK = 0x0A,
	ePACKTYPE_WAPI_PROTO_GKEY_SET_REQU = 0x0B,
	ePACKTYPE_WAPI_PROTO_GKEY_SET_RESP = 0x0C
} eWAIPackType;

#define       MAX_COUNT_RESEND_ACCESSAUTHREQU        3
#define       MAX_COUNT_RESEND_SESSNEGRESP           3

#define       TIMEOUT_ACCESSAUTHREQU_PERIOD      31000
#define       TIMEOUT_SESSNEGRESP_PERIOD         300
#define       ACCESSAUTHREQU_TIMEOUT      200
#define       SESSIONNEGRESP_TIMEOUT	  100

#define   WAPI_ECDH_KEY_LEN          192


#define BKSA_SHA_STR           "base key expansion for key and additional nonce"
#define BKSA_SHA_STR_LEN        (sizeof(BKSA_SHA_STR) - sizeof(char))

#define BK_EXPANSION_LEN             48

void wlan_wapi_iface_receive_pkt_cback(
	uint32 len, uint8 *pkt, void *user_data_ptr);
void wlan_wapi_iface_event_cback(wlan_wapi_iface_event_type *wlan_ev,
			void *user_data_ptr);

uint32  ProcessWAPIProtocolAccessAP(const uint8 * buffer, uint16 bufflen);
uint32  ProcessWAPIProtocolAuthActive(const uint8 * buffer, uint16 bufflen);
uint32  ProcessWAPIProtocolAccessAuthResp(const uint8 * buffer, uint16 bufflen);
uint32  ProcessWAPIProtocolSessNegRequ(const uint8 * buffer, uint16 bufflen);
uint32  ProcessWAPIProtocolSessNegAck(const uint8 * buffer, uint16 bufflen);
uint32  ProcessWAPIProtocolGroupKeyNotice(const uint8 * buffer, uint16 bufflen);

wlan_wapi_iface_return_status_enum_type WAPISendDisconnectEv(void);


#endif /*__WLAN_WAPI_WAIPROCESS_H_*/
