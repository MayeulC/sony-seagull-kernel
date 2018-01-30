/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef __WLAN_WAPI_PACK_H_
#define __WLAN_WAPI_PACK_H_

#include "wlan_wapi_iface_os_svc.h"

/*=============================================================================
WLAN_WAPI_PACK.H

DESCRIPTION

EXTERNALIZED FUNCTIONS


==========================================================================*/

/*===========================================================================

			EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ----------------------------------------------------------

===========================================================================*/

/*===========================================================================

    INCLUDE FILES FOR MODULE

===========================================================================*/

#include "wlan_wapi_structure.h"

uint16 pack_access_auth_requ(const access_auth_requ *pAccess_auth_requ,
			void *buffer, unsigned short bufflen);

uint16 pack_access_auth_requ_to_buffer(
			const access_auth_requ *pAccess_auth_requ,
			void *buffer, unsigned short bufflen);

uint16 c_pack_identity(const identity *pIdentity, void *buffer,
			uint16 offset, unsigned short bufflen);

uint16 c_pack_certificate(const certificate *pCertificate,
			void *buffer, uint16 offset, unsigned short bufflen);

uint16 c_pack_identity_list(const identity_list *pIdentity_list,
			void *buffer, uint16 offset, unsigned short bufflen);

uint16 pack_certificate_vaild_result(const certificate_valid_result
			*pCertificate_valid_result, void * buffer,
			unsigned short bufflen);

uint16 pack_session_key_neg_resp_to_buffer(
			const session_key_neg_resp *pSession_key_neg_resp,
			void * buffer, unsigned short bufflen);

uint16 pack_session_key_neg_resp(
			const session_key_neg_resp *pSession_key_neg_resp,
			void * buffer, unsigned short bufflen);

uint16 pack_groupkey_notify_resp_to_buffer(const groupkey_notify_resp
			*pGroupkey_notify_resp, void * buffer,
			unsigned short bufflen);

uint16 pack_groupkey_notify_resp(
			const groupkey_notify_resp *pGroupkey_notify_resp,
			void * buffer, unsigned short bufflen);


#endif /*__WLAN_WAPI_PACK_H_*/
