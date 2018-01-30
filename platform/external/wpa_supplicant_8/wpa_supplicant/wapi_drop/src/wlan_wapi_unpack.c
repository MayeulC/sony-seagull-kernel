/*=============================================================================
WLAN_WAPI_UNPACK.C

DESCRIPTION

EXTERNALIZED FUNCTIONS


==========================================================================*/

/*===========================================================================

			EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ----------------------------------------------------------

* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright (C) 2012 Sony Mobile Communications AB.
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
#include "wlan_wapi_unpack.h"
#include "wlan_wapi_structure.h"



boolean  bIsSessionKeyAck = FALSE;


uint8 read_byte(const void* buffer,uint16 site)
{
	uint8 result = *(((uint8*)buffer)+site);
	return result;
}


uint16 read_word(const void* buffer,uint16 site)
{
	uint16 result;
	memcpy(&result, (uint8*)buffer+site, 2);
	result = ntohs(result);
	return result;
}



uint16  c_unpack_byte(uint8* content, const void* buffer,
			uint16 offset,uint16 bufflen)
{
	if(offset+1>bufflen)
		return PACK_ERROR;
	*content = read_byte(buffer,offset);
	offset ++;

	return offset;
}


uint16  c_unpack_word(uint16 *content, const void* buffer,
		uint16 offset,uint16 bufflen)
{
	if( offset+2>bufflen )
		return PACK_ERROR;
	*content = read_word(buffer,offset);
	offset += 2;

	return offset;
}


uint16  c_unpack_byte_data(byte_data *p_byte_data,
		const void* buffer, uint16 offset,uint16 bufflen)
{
	offset = c_unpack_byte(&p_byte_data->length, buffer, offset, bufflen);
	if( offset+p_byte_data->length > bufflen )
		return PACK_ERROR;
	memcpy(p_byte_data->data, (uint8*)buffer+offset, p_byte_data->length);
	offset += p_byte_data->length;
	p_byte_data->data[p_byte_data->length] = 0;

	return offset;
}


uint16 c_unpack_sign_data(sign_data *p_comm_data, const void* buffer,
		uint16 offset, uint16 bufflen)
{
	offset = c_unpack_word(&p_comm_data->length, buffer, offset, bufflen);
	if (offset + p_comm_data->length > bufflen)
		return PACK_ERROR;
	memcpy(p_comm_data->data, (uint8 *)buffer+offset, p_comm_data->length);
	offset += p_comm_data->length;
	p_comm_data->data[p_comm_data->length] = 0;

	return offset;
}


uint16 c_unpack_packet_head(packet_head *p_packet_head, const void* buffer,
		uint16 bufflen)
{
	uint16 offset = 0;
	offset = c_unpack_word(&p_packet_head->version, buffer,
			offset, bufflen);
	offset = c_unpack_byte(&p_packet_head->type, buffer,
			offset, bufflen);
	offset = c_unpack_byte(&p_packet_head->subtype, buffer,
			offset, bufflen);
	offset = c_unpack_word(&p_packet_head->reserved, buffer,
			offset, bufflen);
	offset = c_unpack_word(&p_packet_head->length, buffer,
			offset, bufflen);
	offset = c_unpack_word(&p_packet_head->packetnumber, buffer,
			offset, bufflen);
	offset = c_unpack_byte(&p_packet_head->fragmentnumber, buffer,
			offset, bufflen);
	offset = c_unpack_byte(&p_packet_head->identify, buffer, offset,
			bufflen);

	return offset;

}


uint16 c_unpack_sign_arithmetic(sign_arithmetic *p_sign_arithmetic,
			const void * buffer, uint16 offset, uint16 bufflen)
{
	offset = c_unpack_word(&p_sign_arithmetic->length, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR) return PACK_ERROR;
	offset = c_unpack_byte(&p_sign_arithmetic->hash_identify, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR) return PACK_ERROR;
	offset = c_unpack_byte(&p_sign_arithmetic->sign_identify, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR) return PACK_ERROR;

	offset = c_unpack_byte(&p_sign_arithmetic->param_identify, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR) return PACK_ERROR;
	offset = c_unpack_word(&p_sign_arithmetic->param_length, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR) return PACK_ERROR;

	if (p_sign_arithmetic->param_identify == 1)
	{
		if (offset + p_sign_arithmetic->param_length > bufflen)
			return PACK_ERROR;
		memcpy(&p_sign_arithmetic->oid.oid_code,
		(uint8 *)buffer + offset, p_sign_arithmetic->param_length);
		offset += p_sign_arithmetic->param_length;

	}
	else
	{
		return PACK_ERROR;
	}

	return offset;

}


uint16 c_unpack_ecdh_param(ecdh_param *p_ecdh_param, const void * buffer,
			uint16 offset, uint16 bufflen)
{
	offset = c_unpack_byte(&p_ecdh_param->param_identify, buffer,
	offset, bufflen);
	if (offset == PACK_ERROR) return PACK_ERROR;
	offset = c_unpack_word(&p_ecdh_param->param_length, buffer,
	offset, bufflen); if (offset == PACK_ERROR) return PACK_ERROR;

	if (p_ecdh_param->param_identify == 1)
	{
		if (offset + p_ecdh_param->param_length > bufflen)
			return PACK_ERROR;
		memcpy(&p_ecdh_param->oid.oid_code, (uint8 *)buffer + offset,
		p_ecdh_param->param_length);
		offset += p_ecdh_param->param_length;

	}
	else
	{
		return PACK_ERROR;
	}

	return offset;
}


uint16 c_unpack_certificate(certificate *p_certificate, const void * buffer,
			uint16 offset, uint16 bufflen)
{

	offset = c_unpack_word(&p_certificate->cer_identify, buffer,
			offset, bufflen);

	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_word(&p_certificate->cer_length, buffer,
			offset, bufflen);

	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if ( p_certificate->cer_identify == 0x0001 )
	{
		if (offset + p_certificate->cer_length > bufflen)
			return PACK_ERROR;
		memcpy(&p_certificate->cer_X509, (uint8 *)buffer + offset,
		p_certificate->cer_length);
		offset += p_certificate->cer_length;

	}
	else
	{
		return PACK_ERROR;
	}

	return offset;

}


uint16 c_unpack_identity(identity *p_identity, const void * buffer,
			uint16 offset, uint16 bufflen)
{

	offset = c_unpack_word(&p_identity->identity_identify, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR) return PACK_ERROR;

	offset = c_unpack_word(&p_identity->identity_length, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR) return PACK_ERROR;

	if (p_identity->identity_identify == 0x0001)
	{
		if (offset + p_identity->identity_length > bufflen)
			return PACK_ERROR;
		memcpy(&p_identity->cer_der.data, (uint8 *)buffer + offset,
		p_identity->identity_length);
		offset += p_identity->identity_length;
	}
	else
	{
		return PACK_ERROR;
	}


	return offset;

}


uint16 c_unpack_addindex(addindex *p_addindex, const void * buffer,
			uint16 offset, uint16 bufflen)
{
	if (offset + MAC_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_addindex->mac1, (uint8 *)buffer + offset, MAC_LEN);
	offset += MAC_LEN;

	if (offset + MAC_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_addindex->mac2, (uint8 *)buffer + offset, MAC_LEN);
	offset += MAC_LEN;

	return offset;

}


uint16 c_unpack_sign_attribute(sign_attribute *p_sign_attribute,
		const void * buffer, uint16 offset, uint16 bufflen)
{

	offset = c_unpack_byte(&p_sign_attribute->type, buffer,
		offset, bufflen);
	if ((offset == PACK_ERROR) || (p_sign_attribute->type != 1))
		return PACK_ERROR;

	offset = c_unpack_word(&p_sign_attribute->length, buffer,
		offset, bufflen);

	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_identity(&p_sign_attribute->signidentity,
		buffer, offset, bufflen);

	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_sign_arithmetic(&p_sign_attribute->signarithmetic,
		buffer, offset, bufflen);

	if (offset == PACK_ERROR)
		return PACK_ERROR;


	offset = c_unpack_sign_data(&p_sign_attribute->sign, buffer,
		offset, bufflen);

	if (offset == PACK_ERROR)
		return PACK_ERROR;

	return offset;

}

uint16 c_unpack_certificate_valid_result(
certificate_valid_result *p_certificate_valid_result,
const void * buffer, uint16 offset, uint16 bufflen)
{

	offset = c_unpack_byte(&p_certificate_valid_result->type,
			buffer, offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_word(&p_certificate_valid_result->length,
			buffer, offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_certificate_valid_result->random1,
	(uint8 *)buffer + offset, RAND_LEN);
	offset += RAND_LEN;

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_certificate_valid_result->random2,
	(uint8 *)buffer + offset, RAND_LEN);
	offset += RAND_LEN;

	offset = c_unpack_byte(&p_certificate_valid_result->cerresult1,
	buffer, offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_certificate(&p_certificate_valid_result->certificate1,
			buffer, offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_byte(&p_certificate_valid_result->cerresult2, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_certificate(&p_certificate_valid_result->certificate2,
			buffer, offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	return offset;

}


uint16 unpack_auth_active(auth_active *p_auth_active, const void * buffer,
			uint16 bufflen)
{

	uint16 offset = 0;
	packet_head head;
	offset = c_unpack_packet_head(&head, buffer, bufflen);

	offset = c_unpack_byte(&p_auth_active->flag, buffer, offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_auth_active->authidentify,
	(uint8 *)buffer + offset, RAND_LEN);
	offset += RAND_LEN;

	offset = c_unpack_identity(&p_auth_active->localasuidentity, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_certificate(&p_auth_active->certificatestaae, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_ecdh_param(&p_auth_active->ecdhparam, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	return offset;

}


uint16  unpack_access_auth_resp(access_auth_resp *p_access_auth_resp,
const void * buffer, uint16 bufflen)
{

	uint16 offset = 0;
	packet_head head;
	offset = c_unpack_packet_head(&head, buffer, bufflen);

	offset = c_unpack_byte(&p_access_auth_resp->flag, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_access_auth_resp->asuechallenge, (uint8 *)buffer + offset,
		RAND_LEN);
	offset += RAND_LEN;

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_access_auth_resp->aechallenge, (uint8 *)buffer + offset,
		RAND_LEN);
	offset += RAND_LEN;

	offset = c_unpack_byte(&p_access_auth_resp->accessresult, buffer,
		offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_byte_data(&p_access_auth_resp->asuekeydata, buffer,
		offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_byte_data(&p_access_auth_resp->aekeydata, buffer,
		offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_identity(&p_access_auth_resp->staaeidentity, buffer,
		offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_identity(&p_access_auth_resp->staasueidentity, buffer,
		offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if (((p_access_auth_resp->flag & 8) >> 3) == 1)
	{

	    offset = c_unpack_certificate_valid_result(
			&p_access_auth_resp->cervalidresult, buffer,
			offset, bufflen);
	    if (offset == PACK_ERROR)
		    return PACK_ERROR;

		offset = c_unpack_sign_attribute(
			&p_access_auth_resp->asueassign, buffer,
			offset, bufflen);
		if (offset == PACK_ERROR)
			return PACK_ERROR;

		offset = c_unpack_sign_attribute(&p_access_auth_resp->aeassign,
				buffer, offset, bufflen);
		if (offset == PACK_ERROR)
			return PACK_ERROR;

		if (offset == bufflen)
		{
			memset(&p_access_auth_resp->aesign, 0,
				sizeof(p_access_auth_resp->aesign));
			memcpy(&p_access_auth_resp->aesign,
				&p_access_auth_resp->aeassign,
				sizeof(p_access_auth_resp->aeassign));

			memset(&p_access_auth_resp->aeassign, 0,
				sizeof(p_access_auth_resp->aeassign));
			memcpy(&p_access_auth_resp->aeassign,
				&p_access_auth_resp->asueassign,
				sizeof(p_access_auth_resp->asueassign));
			memset(&p_access_auth_resp->asueassign, 0,
				sizeof(p_access_auth_resp->asueassign));
		}

		else if (offset < bufflen)
		{
			offset = c_unpack_sign_attribute(
					&p_access_auth_resp->aesign, buffer,
					offset, bufflen);
			if (offset == PACK_ERROR)
				return PACK_ERROR;

		}
		else
		{
			return PACK_ERROR;
		}

	}
	else
	{
		offset = c_unpack_sign_attribute(&p_access_auth_resp->aesign,
				buffer, offset, bufflen);
		if (offset == PACK_ERROR)
			return PACK_ERROR;
	}

	return offset;

}

uint16  unpack_session_key_neg_requ(
session_key_neg_requ *p_session_key_neg_requ,
const void * buffer, uint16 bufflen)
{

	uint16 offset = 0;
	packet_head head;
	offset = c_unpack_packet_head(&head, buffer, bufflen);


	offset = c_unpack_byte(&p_session_key_neg_requ->flag, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if (offset + BKID_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_session_key_neg_requ->bkid, (uint8 *)buffer + offset,
		BKID_LEN);
	offset += BKID_LEN;


	offset = c_unpack_byte(&p_session_key_neg_requ->uskid, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_addindex(&p_session_key_neg_requ->addid, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_session_key_neg_requ->aechallenge, (uint8 *)buffer + offset,
		RAND_LEN);
	offset += RAND_LEN;

	return offset;

}


uint16 c_unpack_wapi_param_set_2(void* iebuf, const void * buffer,
	uint16 offset, uint16 bufflen)
{
	uint8 t, l;
	offset = c_unpack_byte(&t, buffer, offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;
	offset = c_unpack_byte(&l, buffer, offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if(offset+l>bufflen)
		return PACK_ERROR;
	memcpy(iebuf, (const char*)buffer+offset-2, l+2);
	offset += l;
	return offset;
}


uint16 unpack_session_key_neg_ack(session_key_neg_ack *p_session_key_neg_ack,
	const void * buffer, uint16 bufflen)
{
	uint16 offset = 0;
	packet_head head;
	offset = c_unpack_packet_head(&head, buffer, bufflen);

	offset = c_unpack_byte(&p_session_key_neg_ack->flag, buffer, offset,
			bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if (offset + BKID_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_session_key_neg_ack->bkidentify, (uint8 *)buffer + offset,
		BKID_LEN);
	offset += BKID_LEN;

	offset = c_unpack_byte(&p_session_key_neg_ack->uskid, buffer, offset,
		bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_addindex(&p_session_key_neg_ack->addid, buffer,
		offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if (offset + RAND_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_session_key_neg_ack->asuechallenge, (uint8 *)buffer + offset,
		RAND_LEN);
	offset += RAND_LEN;

	bIsSessionKeyAck = TRUE;

	memset(p_session_key_neg_ack->wie, 0, sizeof(p_session_key_neg_ack->wie));
	offset = c_unpack_wapi_param_set_2(p_session_key_neg_ack->wie, buffer,
		offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if (offset + HMAC_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_session_key_neg_ack->hmac, (uint8 *)buffer + offset,
		HMAC_LEN);
	offset += HMAC_LEN;

	return offset;

}


uint16 unpack_groupkey_notify_requ(groupkey_notify_requ *p_groupkey_notify_requ,
	const void * buffer, uint16 bufflen)
{
	uint16 offset = 0;
	packet_head head;
	offset = c_unpack_packet_head(&head, buffer, bufflen);

	offset = c_unpack_byte(&p_groupkey_notify_requ->flag, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_byte(&p_groupkey_notify_requ->notifykeyindex,
			buffer, offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_byte(&p_groupkey_notify_requ->singlekeyindex,
			buffer, offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	offset = c_unpack_addindex(&p_groupkey_notify_requ->addid, buffer,
			offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if (offset + PN_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_groupkey_notify_requ->pn, (uint8 *)buffer + offset, PN_LEN);
	offset += PN_LEN;


	if (offset + IV_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_groupkey_notify_requ->notifykeyidentify,
		(uint8 *)buffer + offset, IV_LEN);
	offset += IV_LEN;


	offset = c_unpack_byte_data(&p_groupkey_notify_requ->notifykeydata,
		buffer, offset, bufflen);
	if (offset == PACK_ERROR)
		return PACK_ERROR;

	if (offset + HMAC_LEN > bufflen)
		return PACK_ERROR;
	memcpy(&p_groupkey_notify_requ->hmac, (uint8 *)buffer + offset,
		HMAC_LEN);
	offset += HMAC_LEN;

	return offset;

}
