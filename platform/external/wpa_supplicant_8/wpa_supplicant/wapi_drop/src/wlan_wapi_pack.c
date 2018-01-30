/*=============================================================================
WLAN_WAPI_PACK.C

DESCRIPTION

EXTERNALIZED FUNCTIONS


===========================================================================*/

/*===========================================================================

		EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ----------------------------------------------------------

* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.

===========================================================================*/

/*===========================================================================

    INCLUDE FILES FOR MODULE

===========================================================================*/


#include <stdio.h>
#include <memory.h>

#include "wlan_wapi_iface_os_svc.h"
#include "wlan_wapi_iface.h"
#include "wlan_wapi_pack.h"
#include "wlan_wapi_structure.h"

extern boolean bIsSessionKeyAck;
extern boolean bPackBKID;
static int gpktSeqNum = 1;

void write_byte(void* buffer, uint8 content, uint16 site)
{
	*(((uint8*)buffer)+site) = content;
}

void write_word(void* buffer, uint16 content, uint16 site)
{
	content = htons(content);
	memcpy((uint8*)buffer+site, &content, 2);
}


void write_dword(void* buffer, uint32 content, uint16 site)
{
	content = htonl(content);
	memcpy((uint8*)buffer+site, &content, 4);
}


uint16  c_pack_byte(const uint8* content,void* buffer, uint16 offset,
			unsigned short bufflen)
{
	if(offset + 1>bufflen)
		return PACK_ERROR;
	write_byte(buffer, *content, offset);
	offset ++;
	return offset;
}


void  set_packet_data_len(void* buffer, const uint16 the_len)
{
	static uint16 site = 6;
	write_word(buffer, the_len, site);
}


uint16  c_pack_word(const uint16* content, void* buffer,
			uint16 offset, unsigned short bufflen)
{
	if(offset + 2>bufflen)
		return PACK_ERROR;
	write_word(buffer, *content, offset);
	offset += 2;
	return offset;
}


uint16  c_pack_dword(const uint32* content, void* buffer,
			uint16 offset, unsigned short bufflen)
{
	if(offset + 4>bufflen)
		return PACK_ERROR;
	write_dword(buffer, *content, offset);
	offset +=4;
	return offset;
}

uint16  c_pack_byte_data(const byte_data * pData, void * buffer,
		uint16 offset, unsigned short bufflen)
{
	if(offset + pData->length + 1 > bufflen ||
		pData->length > MAX_BYTE_DATA_LEN)
		return PACK_ERROR;

	offset = c_pack_byte(&pData->length,buffer,offset,bufflen);
	if(pData->length == 0)
		return PACK_ERROR;
	memcpy((uint8*)buffer + offset, pData->data, pData->length);
	offset += pData->length;

	return offset;
}


uint16 c_pack_sign_data(const sign_data * pData, void * buffer,
				uint16 offset, unsigned short bufflen)
{
	if (offset + pData->length + 2 > bufflen ||
		pData->length > MAX_COMM_DATA_LEN)
		return PACK_ERROR;

	offset = c_pack_word(&pData->length, buffer, offset, bufflen);
	if (pData->length == 0)
		return PACK_ERROR;
	memcpy((uint8 *)buffer + offset, pData->data, pData->length);
	offset +=pData->length;

	return offset;
}

uint16 c_pack_sign_arithmetic(const sign_arithmetic * pSign_arithmetic,
		void * buffer, uint16 offset, unsigned short bufflen)
{
	int i;

	if (offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pSign_arithmetic->length, buffer, offset,
				bufflen);

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pSign_arithmetic->hash_identify, buffer, offset,
				bufflen);

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pSign_arithmetic->sign_identify, buffer,
				offset, bufflen);

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pSign_arithmetic->param_identify, buffer,
				offset, bufflen);

	if (offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pSign_arithmetic->param_length, buffer,
				offset, bufflen);

	if (pSign_arithmetic->param_identify == 1)
	{
		if (offset + pSign_arithmetic->param_length > bufflen)
			return PACK_ERROR;
		for ( i = 0; i < pSign_arithmetic->param_length; i ++)
		{
			offset = c_pack_byte(&pSign_arithmetic->oid.oid_code[i],
			buffer, offset, bufflen);
		}

	}


	return offset;

}

uint16 c_pack_identity(const identity *pIdentity, void * buffer,
			uint16 offset, unsigned short bufflen)
{
    if (offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pIdentity->identity_identify, buffer,
		offset, bufflen);

	if (offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pIdentity->identity_length, buffer, offset,
				bufflen);

	if (pIdentity->identity_identify == 0x0001)
	{
		if (offset + pIdentity->identity_length > bufflen)
			return PACK_ERROR;
		memcpy((uint8 *)buffer + offset, pIdentity->cer_der.data,
		pIdentity->identity_length);
		offset += pIdentity->identity_length;
	}
	else
	{
		return PACK_ERROR;
	}


	return offset;

}


uint16 c_pack_ecdh_param(const ecdh_param *pEcdh_param, void * buffer,
				uint16 offset, unsigned short bufflen)
{
	int i;

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pEcdh_param->param_identify, buffer,
			offset, bufflen);

	if (offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pEcdh_param->param_length, buffer, offset, bufflen);

	if (pEcdh_param->param_identify == 1)
	{
		if (offset + pEcdh_param->param_length > bufflen)
			return PACK_ERROR;
		for ( i = 0; i < pEcdh_param->param_length; i ++)
		{
			offset = c_pack_byte(&pEcdh_param->oid.oid_code[i],
			buffer, offset, bufflen);
		}
	}

	return offset;
}

uint16 c_pack_sign_attribute(const sign_attribute *pSign_attribute, void * buffer,
uint16 offset, unsigned short bufflen)
{
	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pSign_attribute->type, buffer, offset, bufflen);

	if (offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pSign_attribute->length, buffer, offset, bufflen);

	if (offset + pSign_attribute->length > bufflen)
		return PACK_ERROR;

	offset = c_pack_identity(&pSign_attribute->signidentity, buffer,
			offset, bufflen);

	offset = c_pack_sign_arithmetic(&pSign_attribute->signarithmetic,
			buffer, offset, bufflen);

	offset = c_pack_sign_data(&pSign_attribute->sign, buffer, offset,
			bufflen);

	return offset;
}

uint16 c_pack_addindex(const addindex *pAddindex, void * buffer,
			uint16 offset, unsigned short bufflen)
{
	int i = 0;

	if (offset + MAC_LEN > bufflen)
		return PACK_ERROR;

	for ( i = 0 ; i < MAC_LEN ; i ++)
	{
		offset = c_pack_byte(&pAddindex->mac1[i], buffer, offset,
			bufflen);
	}

	if (offset + MAC_LEN > bufflen)
		return PACK_ERROR;
	for ( i = 0 ; i < MAC_LEN ; i ++)
	{
		offset = c_pack_byte(&pAddindex->mac2[i], buffer, offset,
			bufflen);
	}

	return offset;

}


uint16 c_pack_certificate(const certificate *pCertificate, void * buffer,
			uint16 offset, unsigned short bufflen)
{

	if (offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pCertificate->cer_identify, buffer, offset,
			bufflen);

	if (offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pCertificate->cer_length, buffer, offset,
			bufflen);

	if ( pCertificate->cer_identify == 0x0001 )
	{

		if (offset + pCertificate->cer_length > bufflen)
			return PACK_ERROR;
		memcpy((uint8 *)buffer + offset, &pCertificate->cer_X509,
		pCertificate->cer_length);
		offset += pCertificate->cer_length;

	}
	else
	{
		return PACK_ERROR;
	}

	return offset;

}


uint16 c_pack_bkid(const bkid *pBkid, void * buffer, uint16 offset,
			unsigned short bufflen)
{
	if (offset + BKID_LEN > bufflen)
		return PACK_ERROR;
	memcpy((uint8 *)buffer, &pBkid->bkidentify, BKID_LEN);
	offset += BKID_LEN;
	return offset;
}


uint16 c_pack_wapiparamset(const wapi_param_set *pWapiparamset,
		void * buffer, uint16 offset, unsigned short bufflen)
{
	int i = 0 ;
	uint16 wVer ;
	uint16 wAkmNumber;
	uint16 wSingleCodeNumber;
	uint32 dwAkmList;
	uint32 dwSingleCodeList;
	uint32 dwMultiCode;

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pWapiparamset->elementID, buffer, offset,
			bufflen);

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pWapiparamset->length, buffer, offset, bufflen);

	if (offset + 2 > bufflen)
		return PACK_ERROR;

	wVer = ntohs(pWapiparamset->version);
	offset = c_pack_word(&wVer, buffer, offset, bufflen);

	if (offset + 2 > bufflen)
		return PACK_ERROR;
	wAkmNumber = ntohs(pWapiparamset->akmnumber);

	offset = c_pack_word(&wAkmNumber, buffer, offset, bufflen);


	for ( i = 0 ; i < pWapiparamset->akmnumber ; i ++)
	{
		if (offset + 4 > bufflen)
			return PACK_ERROR;
		dwAkmList = ntohl(pWapiparamset->akmlist[i]);
		offset = c_pack_dword(&dwAkmList, buffer, offset, bufflen);
	}

	if (offset + 2 > bufflen)
		return PACK_ERROR;
	wSingleCodeNumber = ntohs(pWapiparamset->singlecodenumber);

	offset = c_pack_word(&wSingleCodeNumber, buffer, offset, bufflen);

	for (i = 0 ; i < pWapiparamset->singlecodenumber ; i ++)
	{
		if (offset + 4 > bufflen)
			return PACK_ERROR;
		dwSingleCodeList = ntohl(pWapiparamset->singlecodelist[i]);
		offset = c_pack_dword(&dwSingleCodeList, buffer, offset,
				bufflen);
	}

	if (offset + 4 > bufflen)
		return PACK_ERROR;
	dwMultiCode = ntohl(pWapiparamset->multicode);
	offset = c_pack_dword(&dwMultiCode, buffer, offset, bufflen);

	if (offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pWapiparamset->wapiability, buffer, offset,
				bufflen);

	if ((bPackBKID))
	{
		if (offset + 2 > bufflen)
			return PACK_ERROR;
		offset = c_pack_word(&pWapiparamset->bkidnumber, buffer,
					offset, bufflen);

		for ( i = 0 ; i < pWapiparamset->bkidnumber ; i ++)
		{
			if (offset + BKID_LEN > bufflen)
				return PACK_ERROR;
			offset = c_pack_bkid(&pWapiparamset->bkidlist[i], buffer,
						offset, bufflen);
		}

	}

	return offset;

}

uint16 c_pack_identity_list(const identity_list *pIdentity_list, void * buffer,
			 uint16 offset, unsigned short bufflen)
{
	int i;

	if ( offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pIdentity_list->type, buffer, offset, bufflen);

	if ( offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pIdentity_list->length, buffer, offset,
								bufflen);

	if ( offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pIdentity_list->reserved, buffer, offset,
								bufflen);

	if ( offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pIdentity_list->identitynumber, buffer,
							offset, bufflen);


	for ( i = 0 ;  i < pIdentity_list->identitynumber ; i ++)
	{
		if (offset + pIdentity_list->identityset[i].identity_length
				+ 2 + 2 > bufflen)
			return PACK_ERROR;
		offset = c_pack_identity(&pIdentity_list->identityset[i],
					buffer, offset, bufflen);

	}

	return offset;

}

uint16 pack_packet_head(const packet_head *pPacket_head, void * buffer,
					uint16 offset, unsigned short bufflen)
{
	if( bufflen < sizeof(packet_head) )
		return PACK_ERROR;

	offset = c_pack_word(&pPacket_head->version, buffer, offset, bufflen);
	offset = c_pack_byte(&pPacket_head->type, buffer, offset, bufflen);
	offset = c_pack_byte(&pPacket_head->subtype, buffer, offset, bufflen);
	offset = c_pack_word(&pPacket_head->reserved, buffer, offset, bufflen);
	offset = c_pack_word(&pPacket_head->length, buffer, offset, bufflen);
	offset = c_pack_word(&pPacket_head->packetnumber, buffer, offset,
						bufflen);
	offset = c_pack_byte(&pPacket_head->fragmentnumber, buffer, offset,
						bufflen);
	offset = c_pack_byte(&pPacket_head->identify, buffer, offset, bufflen);

	return offset;
}

uint16 pack_access_auth_requ(const access_auth_requ *pAccess_auth_requ,
					void * buffer, unsigned short bufflen)
{
	uint16 offset=0;
	int i = 0 ;

	packet_head head;
	head.version        = 0x0001;
	head.type           = 0x01;
	head.subtype        = 0x04;
	head.reserved       = 0x0000;
	head.length         = 0;
	head.packetnumber   = gpktSeqNum;
	if (gpktSeqNum == 0xffff)
		gpktSeqNum = 1;
	else gpktSeqNum++;
	head.fragmentnumber = 0x00;
	head.identify       = 0x00;
	offset = pack_packet_head(&head, buffer, offset, bufflen);

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pAccess_auth_requ->flag, buffer, offset, bufflen);

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;


	for ( i = 0 ; i < RAND_LEN ; i ++)
	{
		offset = c_pack_byte(&pAccess_auth_requ->authidentify[i],
				buffer, offset, bufflen);
	}

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	for ( i = 0 ; i < RAND_LEN ; i ++)
	{
		offset = c_pack_byte(&pAccess_auth_requ->asuechallenge[i],
				buffer, offset, bufflen);
	}

	if (offset + pAccess_auth_requ->asuekeydata.length + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte_data(&pAccess_auth_requ->asuekeydata, buffer,
					offset, bufflen);

	if (offset +
	pAccess_auth_requ->staasueidentity.identity_length + 2 + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_identity(&pAccess_auth_requ->staasueidentity, buffer,
					offset, bufflen);

	if (offset
	+ pAccess_auth_requ->certificatestaasue.cer_length + 2 + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_certificate(&pAccess_auth_requ->certificatestaasue,
				buffer, offset, bufflen);

	if (offset
	+ pAccess_auth_requ->ecdhparam.param_length + 2 + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_ecdh_param(&pAccess_auth_requ->ecdhparam, buffer,
					offset, bufflen);

	if (((pAccess_auth_requ->flag & 8) >> 3) == 1)
	{
		if (offset +
		 pAccess_auth_requ->asuidentitylist.length + 2 + 1 > bufflen)
			return PACK_ERROR;
		offset = c_pack_identity_list(
		&pAccess_auth_requ->asuidentitylist,
		buffer, offset, bufflen);
	}

	if (offset + pAccess_auth_requ->asuesign.length + 2 + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_sign_attribute(&pAccess_auth_requ->asuesign,
					buffer, offset, bufflen);


    set_packet_data_len(buffer, offset);

	return offset;
}

uint16 pack_access_auth_requ_to_buffer(
				const access_auth_requ *pAccess_auth_requ,
				void * buffer, unsigned short bufflen)
{
	uint16 offset = 0;
	int i = 0 ;

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pAccess_auth_requ->flag, buffer, offset, bufflen);

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;

	for ( i = 0 ; i < RAND_LEN ; i ++)
	{
		offset = c_pack_byte(&pAccess_auth_requ->authidentify[i],
					buffer, offset, bufflen);
	}

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	for ( i = 0 ; i < RAND_LEN ; i ++)
	{
		offset = c_pack_byte(&pAccess_auth_requ->asuechallenge[i],
					buffer, offset, bufflen);
	}

	if (offset + pAccess_auth_requ->asuekeydata.length + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte_data(&pAccess_auth_requ->asuekeydata, buffer,
				offset, bufflen);

    if (offset +
	pAccess_auth_requ->staasueidentity.identity_length + 2 + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_identity(&pAccess_auth_requ->staasueidentity,
		buffer, offset, bufflen);

	if (offset +
	pAccess_auth_requ->certificatestaasue.cer_length + 2 + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_certificate(&pAccess_auth_requ->certificatestaasue,
		buffer, offset, bufflen);

	if (offset + pAccess_auth_requ->ecdhparam.param_length + 2 + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_ecdh_param(&pAccess_auth_requ->ecdhparam, buffer,
		offset, bufflen);

	if (((pAccess_auth_requ->flag & 8) >> 3) == 1)
	{
		if (offset +
			pAccess_auth_requ->asuidentitylist.length + 2 + 1 > bufflen)
			return PACK_ERROR;
		offset = c_pack_identity_list(&pAccess_auth_requ->asuidentitylist,
					buffer, offset, bufflen);
	}


	return offset;
}


uint16 pack_session_key_neg_resp(
const session_key_neg_resp *pSession_key_neg_resp, void * buffer,
unsigned short bufflen)
{
	uint16 offset=0;
	int i = 0 ;
	packet_head head;

    bIsSessionKeyAck = FALSE;

	head.version        = 0x0001;
	head.type           = 0x01;
	head.subtype        = 0x09;
	head.reserved       = 0x0000;
	head.length         = 0;
	head.packetnumber   = gpktSeqNum;
	if (gpktSeqNum == 0xffff) gpktSeqNum = 1;
	else gpktSeqNum++;
	head.fragmentnumber = 0x00;
	head.identify       = 0x00;
	offset = pack_packet_head(&head, buffer, offset, bufflen);

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pSession_key_neg_resp->flag, buffer, offset, bufflen);

	//BKID
	if (offset + BKID_LEN > bufflen)
		return PACK_ERROR;


	for ( i = 0 ; i < BKID_LEN; i ++)
	{
		offset = c_pack_byte(&pSession_key_neg_resp->bkidentify[i], buffer,
						offset, bufflen);
	}

	//USKID
	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pSession_key_neg_resp->uskid, buffer,
				offset, bufflen);

	//ADDID
	if (offset + MAC_LEN * 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_addindex(&pSession_key_neg_resp->addid, buffer,
				offset, bufflen);

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	for (i = 0 ; i < RAND_LEN ; i ++)
	{
		offset = c_pack_byte(&pSession_key_neg_resp->asuechallenge[i],
				buffer, offset, bufflen);
	}

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	for (i = 0 ; i < RAND_LEN ; i ++)
	{
		offset = c_pack_byte(&pSession_key_neg_resp->aechallenge[i], buffer,
					offset, bufflen);
	}

	if (offset + pSession_key_neg_resp->wieasue.length + 1 + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_wapiparamset(&pSession_key_neg_resp->wieasue, buffer,
					offset, bufflen);

	if (offset + HMAC_LEN > bufflen)
		return PACK_ERROR;
	for (i = 0 ; i < HMAC_LEN ; i ++)
	{
		offset = c_pack_byte(&pSession_key_neg_resp->hmac[i], buffer,
					offset, bufflen);
	}


	set_packet_data_len(buffer, offset);

	return offset;
}

uint16 pack_session_key_neg_resp_to_buffer(
const session_key_neg_resp *pSession_key_neg_resp, void * buffer,
unsigned short bufflen)
{
	uint16 offset=0;
	int i = 0 ;

	bIsSessionKeyAck = FALSE;

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pSession_key_neg_resp->flag, buffer,
				offset, bufflen);

	//BKID
	if (offset + BKID_LEN > bufflen)
		return PACK_ERROR;


	for (i = 0 ; i < BKID_LEN; i ++)
	{
		offset = c_pack_byte(&pSession_key_neg_resp->bkidentify[i],
				buffer, offset, bufflen);
	}

	//USKID
	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pSession_key_neg_resp->uskid, buffer,
			offset, bufflen);

	//ADDID
	if (offset + MAC_LEN * 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_addindex(&pSession_key_neg_resp->addid,
			buffer, offset, bufflen);


	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	for (i = 0 ; i < RAND_LEN ; i ++)
	{
		offset = c_pack_byte(&pSession_key_neg_resp->asuechallenge[i],
			buffer, offset, bufflen);
	}

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	for (i = 0 ; i < RAND_LEN ; i ++)
	{
		offset = c_pack_byte(&pSession_key_neg_resp->aechallenge[i],
			buffer, offset, bufflen);
	}

	//WIEasue
	if (offset + pSession_key_neg_resp->wieasue.length + 1 + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_wapiparamset(&pSession_key_neg_resp->wieasue,
			buffer, offset, bufflen);

	return offset;
}

uint16 pack_groupkey_notify_resp(
const groupkey_notify_resp *pGroupkey_notify_resp,
void * buffer, unsigned short bufflen)
{
	uint16 offset=0;
	int i = 0 ;

	packet_head head;
	head.version        = 0x0001;
	head.type           = 0x01;
	head.subtype        = 0x0C;
	head.reserved       = 0x0000;
	head.length         = 0;
	head.packetnumber   = gpktSeqNum;
	if (gpktSeqNum == 0xffff) gpktSeqNum = 1;
	else gpktSeqNum++;
	head.fragmentnumber = 0x00;
	head.identify       = 0x00;

	offset = pack_packet_head(&head, buffer, offset, bufflen);

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pGroupkey_notify_resp->flag,
		buffer, offset, bufflen);

	//MSKID
	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pGroupkey_notify_resp->notifykeyindex,
		buffer, offset, bufflen);

	//USKID
	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pGroupkey_notify_resp->singlekeyindex,
		buffer, offset, bufflen);

	//ADDID
	if (offset + MAC_LEN * 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_addindex(&pGroupkey_notify_resp->addid,
		buffer, offset, bufflen);

	if (offset + IV_LEN > bufflen)
		return PACK_ERROR;


	for (i = 0 ; i < IV_LEN ; i ++)
	{
		offset = c_pack_byte(
			&pGroupkey_notify_resp->notifykeyidentify[i],
			buffer, offset, bufflen);
	}

	if (offset + HMAC_LEN > bufflen)
		return PACK_ERROR;
	for (i = 0 ; i < HMAC_LEN ; i ++)
	{
		offset = c_pack_byte(&pGroupkey_notify_resp->hmac[i],
			buffer, offset, bufflen);
	}

	set_packet_data_len(buffer, offset);

	return offset;
}


uint16 pack_groupkey_notify_resp_to_buffer(
const groupkey_notify_resp *pGroupkey_notify_resp,
void * buffer, unsigned short bufflen)
{
	uint16 offset = 0;
	int i;

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pGroupkey_notify_resp->flag,
			buffer, offset, bufflen);

	//MSKID
	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pGroupkey_notify_resp->notifykeyindex,
		buffer, offset, bufflen);

	//USKID
	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pGroupkey_notify_resp->singlekeyindex,
		buffer, offset, bufflen);

	//ADDID
	if (offset + MAC_LEN * 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_addindex(&pGroupkey_notify_resp->addid,
		buffer, offset, bufflen);

	if (offset + IV_LEN > bufflen)
		return PACK_ERROR;
	for ( i = 0 ; i < IV_LEN ; i ++)
	{
		offset = c_pack_byte(
			&pGroupkey_notify_resp->notifykeyidentify[i],
			buffer, offset, bufflen);
	}


	return offset;
}


uint16 pack_certificate_vaild_result(
const certificate_valid_result *pCertificate_valid_result,
void * buffer, unsigned short bufflen)
{
	uint16 offset = 0;
	int i = 0 ;

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pCertificate_valid_result->type,
			buffer, offset, bufflen);

	if (offset + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_word(&pCertificate_valid_result->length,
			buffer, offset, bufflen);

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;


	for ( i = 0 ; i < RAND_LEN ; i ++)
	{
		offset = c_pack_byte(&pCertificate_valid_result->random1[i],
				buffer, offset, bufflen);
	}

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	for ( i = 0 ; i < RAND_LEN ; i ++)
	{
		offset = c_pack_byte(&pCertificate_valid_result->random2[i],
				buffer, offset, bufflen);
	}

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pCertificate_valid_result->cerresult1, buffer,
				offset, bufflen);

	if (offset +
	pCertificate_valid_result->certificate1.cer_length + 2 + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_certificate(&pCertificate_valid_result->certificate1,
				buffer, offset, bufflen);

	if (offset + 1 > bufflen)
		return PACK_ERROR;
	offset = c_pack_byte(&pCertificate_valid_result->cerresult2, buffer,
				offset, bufflen);

	if (offset +
	pCertificate_valid_result->certificate2.cer_length + 2 + 2 > bufflen)
		return PACK_ERROR;
	offset = c_pack_certificate(&pCertificate_valid_result->certificate2,
				buffer, offset, bufflen);


	return offset;
}
