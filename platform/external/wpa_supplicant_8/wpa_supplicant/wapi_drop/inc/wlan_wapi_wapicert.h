/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef __WLAN_WAPI_WAPICERT_H_
#define __WLAN_WAPI_WAPICERT_H_
/*=============================================================================
WLAN_WAPI_WAICERT.H

DESCRIPTION

EXTERNALIZED FUNCTIONS


=============================================================*/

/*===========================================================================

			EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ----------------------------------------------------------

===========================================================================*/

enum get_certificate_from_file_enum_type{
	eWAI_CERT_NO_ERROR = 0,
	eWAI_CERT_FOPENERROR = 1,
	eWAI_CERT_FSEEKERROR = 2,
	eWAI_CERT_FILEFORMATERROR = 3,
	eWAI_CERT_BEGIN_ASU_CERTIFICATE_NOTFIND = 4,
	eWAI_CERT_END_ASU_CERTIFICATE_NOTFIND = 5,
	eWAI_CERT_BEGIN_USER_CERTIFICATE_NOTFIND = 6,
	eWAI_CERT_END_USER_CERTIFICATE_NOTFIND = 7,
	eWAI_CERT_BEGIN_EC_PRIVATE_KEY_NOTFIND = 8,
	eWAI_CERT_END_EC_PRIVATE_KEY_NOTFIND = 9,
	eWAI_CERT_DECODEBASE64ERROR = 10,
	eWAI_CERT_CERTIFICATE_FORMAT_ERROR = 11,
	eWAI_CERT_GENERIC_ERROR = 12,
};


uint32 certificate_test(certificate * pcert);


uint16 get_identity_from_certificate(const certificate * pCertificate,
				identity *lpIdentity);

uint16 get_issurenameentry_from_certificate(const certificate * pCertificate,
				byte_data * lpIssureName);

uint16 build_sign_attribute_from_signdata(const certificate *pCertificate,
				const byte_data *pSignData,
				sign_attribute *pSignAttribute);

uint16 get_pubkeyvalue_from_certificate(const certificate *pCertificate,
				byte_data *lpPubKeyValue);

uint16 unpack_private_key(private_key *p_private_key,
				const void * buffer, uint16 bufflen);

#endif /*__WLAN_WAPI_WAPICERT_H_*/
