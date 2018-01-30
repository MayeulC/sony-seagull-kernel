/*=============================================================================
WLAN_WAPI_WAICERT.C

DESCRIPTION

EXTERNALIZED FUNCTIONS


==========================================================================*/

/*===========================================================================

			EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ----------------------------------------------------------
3/15/2012   tagrawal  Added fix for  Unhandled Page fault observed on WPA_Supplicant
                      and supplicant crashes when you give details to PEAP AP and
                      try to connect(CR#340182)

* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.

===========================================================================*/

/*===========================================================================

    INCLUDE FILES FOR MODULE

===========================================================================*/



#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "wlan_wapi_iface_os_svc.h"
#include "wlan_wapi_iface.h"
#include "wlan_wapi_waiprocess.h"
#include "wlan_wapi_structure.h"
#include "wlan_wapi_wapicert.h"
#include "wlan_wapi_unpack.h"
#include "wlan_wapi_pack.h"
#include "wlan_wapi_x509.h"

X509* X509_new() { return NULL; }
void X509_free(X509* a) {}


uint16 unpack_private_key(private_key *p_private_key,
const void * buffer, uint16 bufflen)
{
	uint16  offset = 0;
	uint8  tTotal;
	uint8  lTotal;

	memcpy(&tTotal, (uint8 *)buffer + offset, 1);
	offset++;

	memcpy(&lTotal, (uint8 *)buffer + offset, 1);
	offset++;

	memcpy(&p_private_key->tVersion, (uint8 *)buffer + offset, 1);
	offset++;
	memcpy(&p_private_key->lVersion, (uint8 *)buffer + offset, 1);
	offset++;
	if (offset + p_private_key->lVersion > bufflen)
		return PACK_ERROR;
	memcpy(&p_private_key->vVersion, (uint8 *)buffer + offset,
		p_private_key->lVersion);
	offset += p_private_key->lVersion;

	memcpy(&p_private_key->tPrivateKey, (uint8 *)buffer + offset, 1);
	offset++;
	memcpy(&p_private_key->lPrivateKey, (uint8 *)buffer + offset, 1);
	offset++;
	if (offset + p_private_key->lPrivateKey > bufflen)
		return PACK_ERROR;

	memset(p_private_key->vPrivateKey, 0,
		sizeof(p_private_key->vPrivateKey));
	memcpy(p_private_key->vPrivateKey+SECKEY_LEN-p_private_key->lPrivateKey,
		(uint8 *)buffer + offset, p_private_key->lPrivateKey);
	offset += p_private_key->lPrivateKey;
	p_private_key->lPrivateKey  = SECKEY_LEN;

	memcpy(&p_private_key->tSPrivateKeyAlgorithm,
		(uint8 *)buffer + offset, 1);
	offset++;
	memcpy(&p_private_key->lSPrivateKeyAlgorithm,
		(uint8 *)buffer + offset, 1);
	offset++;

	memcpy(&p_private_key->tOID, (uint8 *)buffer + offset, 1);
	offset++;
	memcpy(&p_private_key->lOID, (uint8 *)buffer + offset, 1);
	offset++;
	if (offset + p_private_key->lOID > bufflen)
		return PACK_ERROR;
	memcpy(&p_private_key->vOID, (uint8 *)buffer + offset,
		p_private_key->lOID);
	offset += p_private_key->lOID;

	memcpy(&p_private_key->tSPubkey, (uint8 *)buffer + offset, 1);
	offset++;
	memcpy(&p_private_key->lSPubkey, (uint8 *)buffer + offset, 1);
	offset++;

	memcpy(&p_private_key->tPubkey, (uint8 *)buffer + offset, 1);
	offset++;
	memcpy(&p_private_key->lPubkey, (uint8 *)buffer + offset, 1);
	offset++;
	if (offset + p_private_key->lPubkey > bufflen)
		return PACK_ERROR;
	memcpy(&p_private_key->vPubkey, (uint8 *)buffer + offset,
		p_private_key->lPubkey);
	offset += p_private_key->lPubkey;

	return offset;
}

uint32 certificate_test(certificate * pcert)
{

	X509 *pCerX509 = NULL;

	X509_NAME1	   *pX509Nameissure = NULL;
	X509_NAME1	   *pX509Namesubject = NULL;
	ASN1_INTEGER  *pX509SerialNumber = NULL;

	uint8 bNameissure[256] = {0};
	uint8 bNamesubject[256] = {0};
	uint8 bSerialNumber[256] = {0};
	unsigned char *pNameissure = NULL;
	unsigned char *pNamesubject = NULL;
	unsigned char *pSerialNumber = NULL;

	const unsigned char *p = NULL;


	if (pcert->cer_identify == 0x0001)
	{

		p = pcert->cer_X509;

		pCerX509 = X509_new();

		if (d2i_wapi_X509(&pCerX509, &p, pcert->cer_length) == NULL)
		{
			X509_free(pCerX509);
			return PACK_ERROR;
		}

		pX509Namesubject = X509_get_subject_name_wapi(pCerX509);
		pX509Nameissure = X509_get_issuer_name(pCerX509);
		pX509SerialNumber = X509_get_serialNumber(pCerX509);

		pNameissure = bNameissure;
		pNamesubject = bNamesubject;
		pSerialNumber = bSerialNumber;

		i2d_X509_NAME(pX509Namesubject, &pNamesubject);
		i2d_X509_NAME(pX509Nameissure, &pNameissure);
		i2d_ASN1_INTEGER(pX509SerialNumber, &pSerialNumber);

		X509_free(pCerX509);
	}
	else
	{
		return PACK_ERROR;
	}

	return 0;
}


uint16 get_identity_from_certificate(const certificate * pCertificate,
	identity *lpIdentity)
{

	X509 *pCerX509 = NULL;

	X509_NAME1     *pX509Nameissure = NULL;
	X509_NAME1     *pX509Namesubject = NULL;
	ASN1_INTEGER  *pX509SerialNumber = NULL;

	uint8 bNameissure[256] = {0};
	uint8 bNamesubject[256] = {0};
	uint8 bSerialNumber[256] = {0};
	unsigned char *pNameissure = NULL;
	unsigned char *pNamesubject = NULL;
	unsigned char *pSerialNumber = NULL;

	int namelenissure;
	int namelensubject;
	int snlen;

	uint8 bT;
	uint8 bL;

	const unsigned char *p;

	memset(lpIdentity, 0, sizeof(identity));

	if (pCertificate->cer_identify == 0x0001)
	{
		p = pCertificate->cer_X509;

		pCerX509 = X509_new();

		if (d2i_wapi_X509(&pCerX509, &p, pCertificate->cer_length) == NULL)
		{
			X509_free(pCerX509);
			return PACK_ERROR;
		}

		pX509Namesubject = X509_get_subject_name_wapi(pCerX509);
		pX509Nameissure = X509_get_issuer_name(pCerX509);
		pX509SerialNumber = X509_get_serialNumber(pCerX509);

		pNameissure = bNameissure;
		pNamesubject = bNamesubject;
		pSerialNumber = bSerialNumber;

		namelensubject = i2d_X509_NAME(pX509Namesubject, &pNamesubject);
		namelenissure = i2d_X509_NAME(pX509Nameissure, &pNameissure);
		snlen = i2d_ASN1_INTEGER(pX509SerialNumber, &pSerialNumber);

		lpIdentity->identity_identify = 0x0001;

		memcpy(lpIdentity->cer_der.data, bNamesubject, namelensubject);
		memcpy(lpIdentity->cer_der.data + namelensubject,
			bNameissure, namelenissure);
		bT = 0x02;
		bL = pCerX509->cert_info->serialNumber->length;

		memcpy(lpIdentity->cer_der.data + namelenissure +
			namelensubject, &bT, 1);

		lpIdentity->identity_length = namelenissure
			+ namelensubject + snlen;
		memcpy(lpIdentity->cer_der.data + namelenissure
			+ namelensubject + 1, &bL, 1);
		memcpy(lpIdentity->cer_der.data + namelenissure
			+ namelensubject + 2,
			pCerX509->cert_info->serialNumber->data,
			pCerX509->cert_info->serialNumber->length);
		memcpy(lpIdentity->cer_der.data + namelenissure
			+ namelensubject, bSerialNumber, snlen);

		X509_free(pCerX509);

	}
	else
	{
		return PACK_ERROR;
	}

	return 0;
}

uint16 get_pubkeyvalue_from_certificate (
	const certificate *pCertificate, byte_data *lpPubKeyValue)
{

	X509 *pCerX509 = NULL;

	uint8 bPubKey[PUBKEY_LEN + 2] = {0};
	uint8 bZipType;

	const unsigned char *p;

	memset(lpPubKeyValue, 0, sizeof(byte_data));

	if (pCertificate->cer_identify == 0x0001)
	{
		p = pCertificate->cer_X509;

		pCerX509 = X509_new();

		if (d2i_wapi_X509(&pCerX509, &p, pCertificate->cer_length) == NULL)
		{
			X509_free(pCerX509);
			return PACK_ERROR;
		}

		memcpy(bPubKey, pCerX509->cert_info->key->public_key->data,
			pCerX509->cert_info->key->public_key->length);
		memcpy(&bZipType, bPubKey + 0, 1);

		if (bZipType == 0x04)
		{
			memcpy(lpPubKeyValue->data, bPubKey + 1,
			pCerX509->cert_info->key->public_key->length - 1);
			lpPubKeyValue->length =
			pCerX509->cert_info->key->public_key->length - 1;
		}
		else
		{
			X509_free(pCerX509);
			return PACK_ERROR;
		}

		X509_free(pCerX509);
	}
	else
	{
		return PACK_ERROR;
	}

	return 0;
}

uint16 build_sign_attribute_from_signdata(const certificate *pCertificate,
		const byte_data *pSignData, sign_attribute *pSignAttribute)
{
	identity  tempIdentity;

	uint8 bOID[11] = {0x06, 0x09, 0x2A, 0x81, 0x1C, 0xD7, 0x63,
					0x01, 0x01, 0x02, 0x01};

	memset(&tempIdentity, 0, sizeof(tempIdentity));

	pSignAttribute->type = 1;
	if (get_identity_from_certificate(pCertificate, &tempIdentity) == 0)
	{
		memcpy(&pSignAttribute->signidentity, &tempIdentity,
			sizeof(tempIdentity));

		pSignAttribute->signarithmetic.hash_identify = 1;
		pSignAttribute->signarithmetic.sign_identify = 1;
		pSignAttribute->signarithmetic.param_identify = 1;

		pSignAttribute->signarithmetic.param_length = 11;
		memcpy(pSignAttribute->signarithmetic.oid.oid_code, bOID, 11);

		pSignAttribute->signarithmetic.length = 1 + 1 + 1 + 2 + 11;

		pSignAttribute->sign.length = pSignData->length;
		memcpy(pSignAttribute->sign.data, pSignData->data,
			pSignData->length);

		pSignAttribute->length =
		pSignAttribute->signidentity.identity_length
		+ 2 + 2
		+ pSignAttribute->signarithmetic.length + 2
		+ pSignAttribute->sign.length + 2 ;
		return 0;
	}

	return 0;
}

uint16 get_issurenameentry_from_certificate(
const certificate * pCertificate, byte_data * lpIssureName)
{
	X509 *pCerX509 = NULL;

	X509_NAME1     *pX509Nameissure = NULL;
	uint8 bNameissure[256] = {0};
	unsigned char *pNameissure = NULL;
	int namelenissure = 0;
	const unsigned char *p = NULL;

	memset(lpIssureName, 0, sizeof(byte_data));

	if (pCertificate->cer_identify == 0x0001)
	{
		p = pCertificate->cer_X509;

		pCerX509 = X509_new();

		if (d2i_wapi_X509(&pCerX509, &p, pCertificate->cer_length) == NULL)
		{
			X509_free(pCerX509);
			return PACK_ERROR;
		}

		pX509Nameissure = X509_get_issuer_name(pCerX509);

		pNameissure = bNameissure;

		namelenissure = i2d_X509_NAME(pX509Nameissure, &pNameissure);

		lpIssureName->length = namelenissure;
		memcpy(lpIssureName->data, bNameissure, namelenissure);

		X509_free(pCerX509);

	} else{
		return PACK_ERROR;
	}

	return 0;
}
