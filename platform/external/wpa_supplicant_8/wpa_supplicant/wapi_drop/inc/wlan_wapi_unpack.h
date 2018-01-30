/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef __WLAN_WAPI_UNPACK_H_
#define __WLAN_WAPI_UNPACK_H_

/*==================================================================
WLAN_WAPI_UNPACK.H

DESCRIPTION

EXTERNALIZED FUNCTIONS


======================================================================*/

/*==================================================================

			EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ----------------------------------------------------------

===========================================================================*/


#include "wlan_wapi_structure.h"


uint16 c_unpack_packet_head(packet_head *p_packet_head, const void* buffer,
			uint16 bufflen);

uint16  c_unpack_byte(uint8* content, const void* buffer, uint16 offset,
			uint16 bufflen);

uint16  c_unpack_word(uint16 *content, const void* buffer, uint16 offset,
			uint16 bufflen);

uint16 unpack_auth_active(auth_active *p_auth_active, const void * buffer,
			uint16 bufflen);

uint16 c_unpack_identity(identity *p_identity, const void * buffer,
			uint16 offset, uint16 bufflen);

uint16 c_unpack_certificate(certificate *p_certificate, const void * buffer,
			uint16 offset, uint16 bufflen);

uint16 c_unpack_ecdh_param(ecdh_param *p_ecdh_param, const void * buffer,
			uint16 offset, uint16 bufflen);

uint16  unpack_access_auth_resp(access_auth_resp *p_access_auth_resp,
			const void * buffer, uint16 bufflen);

uint16  unpack_session_key_neg_requ(
			session_key_neg_requ *p_session_key_neg_requ,
			const void * buffer, uint16 bufflen);

uint16 unpack_session_key_neg_ack(session_key_neg_ack *p_session_key_neg_ack,
			const void * buffer, uint16 bufflen);

uint16 unpack_groupkey_notify_requ(groupkey_notify_requ *p_groupkey_notify_requ,
			const void * buffer, uint16 bufflen);

#endif /*__WLAN_WAPI_UNPACK_H_*/
