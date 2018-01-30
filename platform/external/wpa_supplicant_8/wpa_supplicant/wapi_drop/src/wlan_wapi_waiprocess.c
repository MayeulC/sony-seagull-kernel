/*
 * Partly modified 2012-2013 Sony Mobile Communications AB.
 */
/*=============================================================================
WLAN_WAPI_WAPIPROCESS.C

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
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.

===========================================================================*/

/*===========================================================================

    INCLUDE FILES FOR MODULE

===========================================================================*/

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "stdlib.h"
#include "keystore_get.h"

/*WAPI IFACE*/
#include "wlan_wapi_iface_os_svc.h"
#include "wlan_wapi_iface.h"

/*WAPI Supplicant*/
#include "wlan_wapi_waiprocess.h"
#include "wlan_wapi_structure.h"
#include "wlan_wapi_unpack.h"
#include "wlan_wapi_pack.h"
#include "wlan_wapi_ecc.h"
#include "wlan_wapi_wapiinfoerror.h"
#include "wlan_wapi_wpi_pcrypt.h"
#include "wlan_wapi_wapicert.h"

#include "common.h"
#include "defs.h"

extern uint32 wapi_handshake_err;

extern void wapi_supplicant_key_negotiation_state_report(enum wpa_states state);
extern enum wpa_states wapi_supplicant_get_state();

/*================================================================

    LOCAL DEFINITIONS AND DECLARATIONS FOR MODULE

    This section contains local definitions for constants, macros, types,
    variables and other items needed by this module.

====================================================================*/

#define WAPI_AKM_LENGTH		0x0001;
#define WAPI_SINGLECODE_LENGTH  0x0001;
#define WAPI_PROTO_VERSION	0x0001;

#define BUFF_SPLIT_SIZE		8192
#define TX_DATA_BUFF_SIZE	(BUFF_SPLIT_SIZE * 2)
#define RX_DATA_BUFF_SIZE	(BUFF_SPLIT_SIZE * 2)
#define CERT_MGMT_BUFF_SIZE	(BUFF_SPLIT_SIZE * 4)
#define CERT_PARSING_BUFF_START (TX_DATA_BUFF_SIZE+RX_DATA_BUFF_SIZE \
				+ CERT_MGMT_BUFF_SIZE)

#define  WAPI_MEM_NEEDED	MAX_DATA_LEN*2 + WAPI_SIZEOF_IDENTITY \
				+ WAPI_SIZEOF_CERTIFICATE


void *g_wapi_iface_handle	= NULL;
void *p_user_data			= NULL;

timer_t   nTmAccessAuthRequ= 0;
timer_t   nTmSessionNegResp= 0;

wlan_wapi_iface_connect_event_type g_connect_data;
WAI_PROCESS_STATUS   g_eWaiStatus = WAIPS_NONE;

uint8	g_bSTAMac[WLAN_WAPI_IFACE_MAC_ADDR_LEN];	/*STA MAC address*/
uint8	g_bAPBSSIDMac[WLAN_WAPI_IFACE_MAC_ADDR_LEN];	/*AP  MAC address*/
uint8	g_ieAssocAp[WLAN_WAPI_IFACE_WAPI_IE_MAX_LEN] = {0};


/* buffer mgmt */
static uint8 gBufferPtr[WAPI_MEM_NEEDED];
uint8  *senddatabuffer = gBufferPtr;
uint16 nSendPacketLen;


/* fragment assembly */
int   nCurrPackLenWLAN		= 0;
uint8  bPacketNumberWLAN[2] = {0x00, 0x00};
uint8  bFragmentNumberWLAN	= 0;
eWAIPackType   nPacketSubTypeWLAN = ePACKTYPE_WAPI_PROTO_UNKNOWN;

/* packet transmission */
int  nNumResendAccessAuthRequ	= 0;
int  nCountResendAccessAuthRequ = 0;
int  nNumResendSessNegResp		= 0;
int  nCountResendSessNegResp	= 0;

/* Key derivation */
uint8  bx[24];  /*Temp Private Key*/
byte_data bxP;	/*Temp Public Key*/
uint8  bBK[16];	/*Base Key*/
__attribute__ ((aligned(4)))
/*unicast*/
uint8  bUEK[16];
uint8  bUCK[16];
uint8  bMAK[16];
uint8  bKEK[16];

/*multicast*/
uint8  bNMK[16];
uint8  bNEK[16];
uint8  bNCK[16];

boolean bFirstSessionKey = TRUE;
uint8	bUSKIDSA		= 0;
uint8	bUSKIDSARec	= 0;

uint8	bLastAEChallenge[RAND_LEN];
uint8	bLastAuthID[RAND_LEN];
uint8	bAsueChallenge[RAND_LEN];

boolean  bPackBKID	  = FALSE;
boolean  bUnPackBKID  = FALSE;


auth_active			   AuthActivePacket;
access_auth_requ       AccessAuthRequPacket;
access_auth_resp       AccessAuthRespPacket;
session_key_neg_requ   SessionKeyNegRequPacket;
session_key_neg_resp   SessionKeyNegRespPacket;
session_key_neg_ack    SessionKeyNegAckPacket;
groupkey_notify_requ   GroupKeyNotifyPacket;
groupkey_notify_resp   GroupKeyRespPacket;

identity *pIdentitySTAae = NULL;	/*identity identitySTAae*/
certificate *pCerSTAae	 = NULL;	/*STAae certificate*/

struct STA_CERTIFICATE_PARAM
{
    certificate  cerSTAasue;
    byte_data    staSecKey;
    certificate  cerASUSTAasue;
};


typedef struct {
  unsigned long Data1;
  unsigned short Data2;
  unsigned short Data3;
  unsigned char Data4[8];
} GUID;

// save system certificate
struct STA_CERTIFICATE_PARAM *g_pStaCertificateParam = NULL;
struct STA_CERTIFICATE_PARAM g_StaCertificateParam;

unsigned long RandomInit[16] = {0x5c365c36, 0x5c365c36, 0x5c365c36,0x5c365c36};


static void TimerProcResendAccessAuthRequ(uint32 arg);
static void TimerProcResendSessNegResp(uint32 arg);
static boolean WAPIProtocolSend88B4Packet(const uint8* buffer, uint16 bufflen);



/*=====================================================================

			FUNCTION DEFINITIONS

======================================================================*/



void Initialization(uint32 max_mtu_size)
{
	uint32 arg = 0;


	g_wapi_iface_handle = wlan_wapi_iface_get_handle();

	if( g_wapi_iface_handle == NULL )
	{
		wpa_printf(MSG_ERROR, "WAPI: g_wapi_iface_handle is NULL");
	}
	else
	{
		wpa_printf(MSG_DEBUG, " %s: WAPI: Initializing WAPI Supplicant",
			__func__);
		ECC_Init();

		/*create all timers here*/
		nTmSessionNegResp =0;
		nTmAccessAuthRequ =0;
		g_eWaiStatus = WAIPS_IDEL;
		wpa_printf(MSG_ERROR, " %s: WAPI:set Staues=%d ",
			__func__,g_eWaiStatus);

	}

	return;
}


wlan_wapi_iface_start_ind_cback_type TE_WAPI_ASUE_Init(void)
{
	wlan_wapi_iface_start_ind_cback_type pfun;

	wpa_printf(MSG_DEBUG, " %s: WAPI: ASUE INIT ",__func__);

	pfun = Initialization;
	Initialization(255);

	return pfun;

}

void TE_WAPI_ASUE_Deinit(void)
{
	wlan_wapi_iface_cmd_type	cmd;

	g_eWaiStatus = WAIPS_NONE;

	wpa_printf(MSG_DEBUG, " %s: WAPI: ASUE DEINIT ",__func__);
	wpa_printf(MSG_DEBUG, "WAPI: wapi_sm statues is %d\n" ,g_eWaiStatus);

	wpa_printf(MSG_DEBUG, "WAPI: Deinitializing WAPI Supplicant");

	wpa_printf(MSG_INFO, " %s: nTmSessionNegResp %p, nTmAccessAuthRequ %p",
			__func__, nTmSessionNegResp, nTmAccessAuthRequ);
	if(nTmAccessAuthRequ != NULL)
		wlan_wapi_iface_delete_timer(nTmAccessAuthRequ);

	if(nTmSessionNegResp != NULL)
		wlan_wapi_iface_delete_timer(nTmSessionNegResp);

	if( NULL != g_wapi_iface_handle)
	{
		wlan_wapi_iface_release_handle(g_wapi_iface_handle);
	}

	return;

}


wlan_wapi_iface_return_status_enum_type WAPISendDisconnectEv()
{
	wlan_wapi_iface_cmd_type cmd_type;
	wlan_wapi_iface_return_status_enum_type ret;

	cmd_type.cmd_id = WLAN_WAPI_IFACE_CMD_DISCONNECT;

	ret = wlan_wapi_iface_ioctl(g_wapi_iface_handle,&cmd_type);

	if( ret == WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS )
	{
		wpa_printf(MSG_ERROR,
			"WAPI: Posted %d event successfully",
			WLAN_WAPI_IFACE_CMD_DISCONNECT);

		return WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS;
	}

	return WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE;
}

static void TimerProcResendAccessAuthRequ(uint32 arg)
{

	wlan_wapi_iface_auth_result_type res;
	wpa_printf(MSG_INFO, "WAPI: wapi_sm statues is %d\n" ,g_eWaiStatus);

	if(g_eWaiStatus != WAIPS_AUTHING)
	{
		wlan_wapi_iface_stop_timer(nTmAccessAuthRequ);
		return;
	}

	if (nNumResendAccessAuthRequ >= MAX_COUNT_RESEND_ACCESSAUTHREQU)
	{
		wpa_printf(MSG_ERROR,
		"WAPI: Resend AccessAuthRequ is MAX_COUNT");

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_MSG_TIMEOUT;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);
		wlan_wapi_iface_stop_timer(nTmAccessAuthRequ);
		wlan_wapi_iface_delete_timer(nTmAccessAuthRequ);
		nTmAccessAuthRequ = 0;
		nNumResendAccessAuthRequ = 0;
		return;
	}
	else
	{
		if (nCountResendAccessAuthRequ >
		TIMEOUT_ACCESSAUTHREQU_PERIOD / /*100*/ACCESSAUTHREQU_TIMEOUT)
		{
			//resend
			if (WAPIProtocolSend88B4Packet(senddatabuffer,
			nSendPacketLen))
			{
				wpa_printf(MSG_ERROR,
				"WAPI: Resend AccessAuthRequ retries %d",
				nNumResendAccessAuthRequ);

				nNumResendAccessAuthRequ ++;
				nCountResendAccessAuthRequ = 0;
			}
			else //send fail
			{
				wpa_printf(MSG_ERROR,
				"WAPI: Resend AccessAuthRequ failed");

				res.result		=
				WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
				res.failure_reason	=
				WLAN_WAPI_IFACE_AUTH_FAIL_REASON_UNKNOWN;

				wlan_wapi_iface_auth_result_ind(
				g_wapi_iface_handle, res);
				wlan_wapi_iface_stop_timer(nTmAccessAuthRequ);
				wlan_wapi_iface_delete_timer(nTmAccessAuthRequ);
				nTmAccessAuthRequ = 0;

			}
		}
		else
		{
			//Resend count
			nCountResendAccessAuthRequ ++;
		}
	}

	return;

}

static void TimerProcResendSessNegResp(uint32 arg)
{
	wlan_wapi_iface_auth_result_type res;
       wpa_printf(MSG_DEBUG, "WAPI: wapi_sm statues is %d\n" ,g_eWaiStatus);

	wpa_printf(MSG_DEBUG, " %s WAPI: Unicast Neg. Req send Timer Expired ",
			__func__);

	if(g_eWaiStatus != WAIPS_KEY_NEGING)
	{
		wlan_wapi_iface_stop_timer(nTmSessionNegResp);
		return;
	}

	if (nNumResendSessNegResp >= MAX_COUNT_RESEND_SESSNEGRESP)
	{
		wpa_printf(MSG_ERROR, "WAPI: Resend SessNegResp is MAX_COUNT");

		res.result		= WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason	=
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_UNKNOWN;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);
		wlan_wapi_iface_stop_timer(nTmSessionNegResp);
		wlan_wapi_iface_delete_timer(nTmSessionNegResp);
		nNumResendSessNegResp =0;

		nTmSessionNegResp = 0;
		return;
	}
	else
	{
		if (nCountResendSessNegResp >
		TIMEOUT_SESSNEGRESP_PERIOD / /*100*/SESSIONNEGRESP_TIMEOUT)
		{
			//resend
			if (WAPIProtocolSend88B4Packet(senddatabuffer,
				nSendPacketLen))
			{
				wpa_printf(MSG_ERROR,
				"WAPI: Resend SessNegResp retries %d",
				nNumResendSessNegResp);

				nNumResendSessNegResp ++;
				nCountResendSessNegResp = 0;
			}
			else //send fail
			{
				wpa_printf(MSG_ERROR,
				"WAPI: Resend SessNegResp failed");

				res.result =
				WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
				res.failure_reason =
				WLAN_WAPI_IFACE_AUTH_FAIL_REASON_UNKNOWN;

				wlan_wapi_iface_auth_result_ind(
				g_wapi_iface_handle, res);
				wlan_wapi_iface_stop_timer(nTmSessionNegResp);
				wlan_wapi_iface_delete_timer(nTmSessionNegResp);

				nTmSessionNegResp = 0;
			}
		}
		else
		{
			//add count
			nCountResendSessNegResp ++;
		}
	}

	return;

}


boolean  GetBKFromPreShareKey(uint8 * cPreShareKey,
	wlan_wapi_iface_psk_passphrase_enum_type eShareKeyType, uint8 *pBK)
{
	boolean bHaveBK = FALSE;

	int lenPreShareKey = 0;
	uint8 bPreShareKey[128] = {0};
	uint8 bKey0, bKey1;
	char S1[2], S2[2];
	int i;
	wpa_printf(MSG_DEBUG, "%s WAPI: Shared Key Type:%d ",
			__func__,eShareKeyType);

	if (eShareKeyType == WLAN_WAPI_IFACE_PSK_PASSPHRASE_TYPE_ASCII)
	{
		lenPreShareKey = strlen((char *)cPreShareKey);
		prf_preshared((unsigned char *)cPreShareKey, lenPreShareKey, pBK);
		bHaveBK = TRUE;
	}
	else if (eShareKeyType == WLAN_WAPI_IFACE_PSK_PASSPHRASE_TYPE_HEX)
	{
		lenPreShareKey = strlen((char *)cPreShareKey);
		lenPreShareKey = lenPreShareKey / 2;

		for (i = 0 ; i < lenPreShareKey ; i ++)
		{
			switch((char)cPreShareKey[i * 2])
			{
			case 'a':
				bKey0 = 10;
				break;
			case 'A':
				bKey0 = 10;
				break;
			case 'b':
				bKey0 = 11;
				break;
			case 'B':
				bKey0 = 11;
				break;
			case 'c':
				bKey0 = 12;
				break;
			case 'C':
				bKey0 = 12;
				break;
			case 'd':
				bKey0 = 13;
				break;
			case 'D':
				bKey0 = 13;
				break;
			case 'e':
				bKey0 = 14;
				break;
			case 'E':
				bKey0 = 14;
				break;
			case 'f':
				bKey0 = 15;
				break;
			case 'F':
				bKey0 = 15;
				break;
			default:
				{
					S1[0] = (char)cPreShareKey[i * 2];
					S1[1] = '\0';
					bKey0 = atoi((const char*)&S1[0]);
				}
				break;
			}

			switch((char)cPreShareKey[i * 2 + 1])
			{
			case 'a':
				bKey1 = 10;
				break;
			case 'A':
				bKey1 = 10;
				break;
			case 'b':
				bKey1 = 11;
				break;
			case 'B':
				bKey1 = 11;
				break;
			case 'c':
				bKey1 = 12;
				break;
			case 'C':
				bKey1 = 12;
				break;
			case 'd':
				bKey1 = 13;
				break;
			case 'D':
				bKey1 = 13;
				break;
			case 'e':
				bKey1 = 14;
				break;
			case 'E':
				bKey1 = 14;
				break;
			case 'f':
				bKey1 = 15;
				break;
			case 'F':
				bKey1 = 15;
				break;
			default:
				{
					S2[0] = (char)cPreShareKey[i * 2 + 1];
					S2[1] = '\0';
					bKey1 = atoi((const char*)&S2[0]);
				}
				break;
			}

			bPreShareKey[i] = bKey0 * 16 + bKey1;
		}

		prf_preshared(bPreShareKey, lenPreShareKey, pBK);

		bHaveBK = TRUE;
	}
	else
	{
		bHaveBK = FALSE;
	}

	return bHaveBK;
}


//Base64
static char GetBase64Value(char ch)
{
	if ((ch >= 'A') && (ch <= 'Z'))
		return ch - 'A';
	if ((ch >= 'a') && (ch <= 'z'))
		return ch - 'a' + 26;
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0' + 52;
	switch (ch)
	{
	case '+':
		return 62;
	case '/':
		return 63;
	case '=': /* base64 padding */
		return 0;
	default:
		return 0;
	}
}

static int Base64Dec(unsigned char *buf,const unsigned char*text,int size)
{
	char* ptemp = NULL;

	if(size%4)
		return -1;
	unsigned char chunk[4];
	int parsenum=0;
	while ( size>0 )
	{
		chunk[0] = GetBase64Value(text[0]);
		chunk[1] = GetBase64Value(text[1]);
		chunk[2] = GetBase64Value(text[2]);
		chunk[3] = GetBase64Value(text[3]);

		*buf++ = (chunk[0] << 2) | (chunk[1] >> 4);
		*buf++ = (chunk[1] << 4) | (chunk[2] >> 2);
		*buf++ = (chunk[2] << 6) | (chunk[3]);

		text+=4;
		size-=4;
		parsenum+=3;
	}
	ptemp = (char*)(buf - 2);

	if (*ptemp == '\0')
		parsenum--;
	if (*(ptemp+1) == '\0')
		parsenum--;

    return parsenum;
}


static int generate_random( unsigned long * r)
{
	char CatTmpKey[256] = "pairwise key expansion for infrastructure unicast";
	char tmpStr[17] = "";
	GUID guid = {0};

	RandomInit[0]++;
	if(RandomInit[0] == 0)
	{
		RandomInit[1]++;
		if(RandomInit[1] == 0)
		{
			RandomInit[2]++;
			if(RandomInit[2] == 0)
			{
				RandomInit[3]++;
			}
		}
	}

	r[0] = guid.Data1;
	*((unsigned short*)r + 2) = guid.Data2;
	*((unsigned short*)r + 3) = guid.Data3;
	*((unsigned char *)r + 8) = guid.Data4[0];
	*((unsigned char *)r + 9) = guid.Data4[1];
	*((unsigned char *)r +10) = guid.Data4[2];
	*((unsigned char *)r +11) = guid.Data4[3];
	*((unsigned char *)r +12) = guid.Data4[4];
	*((unsigned char *)r +13) = guid.Data4[5];
	*((unsigned char *)r +14) = guid.Data4[6];
	*((unsigned char *)r +15) = guid.Data4[7];


	memcpy(tmpStr, (unsigned char *)RandomInit, 16);
	strcat(CatTmpKey, tmpStr);
	prf_hmac_sha256((uint8 *)CatTmpKey, strlen(CatTmpKey), (uint8 *)r,
			16, (uint8 *)r, 16);

	return 0;
}

// Verify the Private and public Key
static boolean VerifyKey(uint8 *Private,uint8 *PublicKey)
{
	Point pubKey;
	unsigned int Pubx[6*4]={0};
	unsigned int Puby[6*4]={0};
	unsigned int privateKey[6*4];
	int privateKeyLen;
	int   ret = 0;
	unsigned char tmpTest[512]={0};
	unsigned char tmpSign[48];
	int SignLen;

	pubKey.x = Pubx;
	pubKey.y = Puby;

	// get the public key and private key
	OctetStringToPubKey(PublicKey, PUBKEY_LEN, &pubKey);
	OctetStringToPriKey(Private, SECKEY_LEN, privateKey, &privateKeyLen);
	memset(tmpTest, 0x88, 512);

	SignLen = Sign_With_Private_Key(tmpSign, tmpTest, sizeof(tmpTest),
		privateKey, privateKeyLen);

	ret = Verify_With_Public_Key(tmpTest, sizeof(tmpTest), tmpSign,
				SignLen, pubKey);

	return ret == 0 ? FALSE:TRUE;
}

static uint32 wapi_get_X509_cert(char *pUri, certificate *pCert)
{
	uint8_t *pCertText = NULL;
	int certTextLen = -1;
	u8 *pFormatedCertText = NULL;
	int formatedCertTextLen = -1;
	int formatedCertTextPos = 0;
	char seps[] = "\n\r";
	char *pToken = NULL;
	int tokenLen = -1;
	int base64result = -1;
	uint32 ret = eWAI_CERT_CERTIFICATE_FORMAT_ERROR;

	wpa_printf(MSG_DEBUG, "[%s] WAPI: Loading certificate uri: %s", __func__, pUri);

	// inparam checks
	if (NULL == pCert)
	{
		wpa_printf(MSG_ERROR, "WAPI: Invalid certificate pointer");
		goto cleanup;
	}
	if (NULL == pUri || 0 != strncmp("keystore://", pUri, 11))
	{
		wpa_printf(MSG_ERROR, "WAPI: Invalid uri");
		goto cleanup;
	}

	// get keystore text
	certTextLen = keystore_get(&pUri[11], strlen(&pUri[11]), &pCertText);
	if (0 >= certTextLen)
	{
		wapi_handshake_err = wapi_err_KeystoreError;
		wpa_printf(MSG_ERROR, "WAPI: Failed to load certificate");
		goto cleanup;
	}
	// '\0' is missed at the string end of pCertText
	// realloc to add string ending for strtok
	if (0 != pCertText[certTextLen]) {
		char *tmp = realloc(pCertText, certTextLen + 1);
		if (NULL != tmp) {
			pCertText = tmp;
			pCertText[certTextLen] = 0;
		} else {
			wpa_printf(MSG_ERROR,
				"WAPI: Failed to reallocate memory for keystore text");
			goto cleanup;
		}
	}
	// format keystore text (remove start and end tag)
	pFormatedCertText = os_malloc(certTextLen);
	if (NULL == pFormatedCertText)
	{
		wpa_printf(MSG_ERROR,
			"WAPI: Failed to allocate memory for formated keystore text");
		goto cleanup;
	}
	memset(pFormatedCertText, 0, certTextLen);
	pToken = strtok(pCertText, seps);
	while (NULL != pToken)
	{
		tokenLen = strlen(pToken);
		if (pToken[0] != '-')
		{
			memcpy(&(pFormatedCertText[formatedCertTextPos]), pToken, tokenLen);
			formatedCertTextPos += tokenLen;
		}
		pToken = strtok(NULL, seps);
	}

	// create X509 cert from formated text
	pCert->cer_identify = 0x0001; //1 = X509
	base64result = Base64Dec(
		(unsigned char *)&(pCert->cer_X509), pFormatedCertText, formatedCertTextPos);
	if (0 > base64result)
	{
		wpa_printf(MSG_ERROR, "WAPI: Base 64 decoding failed");
		goto cleanup;
	}
	pCert->cer_length = (uint16)base64result;

	// all clear
	ret = eWAI_CERT_NO_ERROR;

cleanup:
	if (pCertText)
		os_free(pCertText);
	if (pFormatedCertText)
		os_free(pFormatedCertText);

	return ret;
}

static uint32 wapi_load_certificates()
{
	uint32 ret;
	certificate userKeyCert;
	private_key privateKey;
	byte_data bdPubKey;

	// AS cert
	ret = wapi_get_X509_cert(
		(char*)g_connect_data.config_params.auth_info.as_cert_info.cert_file_uri,
		&(g_pStaCertificateParam->cerASUSTAasue));
	if (ret != eWAI_CERT_NO_ERROR)
		goto end;

	if (0 != certificate_test(&(g_pStaCertificateParam->cerASUSTAasue)))
	{
		ret = eWAI_CERT_CERTIFICATE_FORMAT_ERROR;
		wpa_printf(MSG_ERROR, "AS Certificate test failed");
		goto end;
	}

	// User cert
	ret = wapi_get_X509_cert(
		(char*)g_connect_data.config_params.auth_info.user_cert_info.cert_file_uri,
		&(g_pStaCertificateParam->cerSTAasue));
	if (ret != eWAI_CERT_NO_ERROR)
		goto end;

	if (0 != certificate_test(&(g_pStaCertificateParam->cerSTAasue)) )
	{
		ret = eWAI_CERT_CERTIFICATE_FORMAT_ERROR;
		wpa_printf(MSG_ERROR, "User Certificate test failed");
		goto end;
	}

	// User key
	ret = wapi_get_X509_cert(
		(char*)g_connect_data.config_params.auth_info.user_key_cert_info.cert_file_uri,
		&userKeyCert);
	if (ret != eWAI_CERT_NO_ERROR)
		goto end;

	unpack_private_key(&privateKey, &(userKeyCert.cer_X509), userKeyCert.cer_length);

	memset(&bdPubKey, 0, sizeof(bdPubKey));

	if (get_pubkeyvalue_from_certificate(&(g_pStaCertificateParam->cerSTAasue), &bdPubKey) != 0)
	{
		ret = eWAI_CERT_CERTIFICATE_FORMAT_ERROR;
		wpa_printf(MSG_ERROR, "Failed to get public key");
		goto end;
	}

	if (!VerifyKey(privateKey.vPrivateKey, bdPubKey.data))
	{
		ret = eWAI_CERT_CERTIFICATE_FORMAT_ERROR;
		wpa_printf(MSG_ERROR, "Failed to verify key");
		goto end;
	}

	g_pStaCertificateParam->staSecKey.length = SECKEY_LEN;
	memcpy(g_pStaCertificateParam->staSecKey.data, privateKey.vPrivateKey, SECKEY_LEN);

end:
	return ret;
}

static boolean  VerifyPacketSignData(const uint8 * buffer, const uint16 bufflen,
		const sign_data * pSignData, const byte_data * cerPubKey)
{
	boolean		bVerify = FALSE;

	uint8		tempPubKey[PUBKEY_LEN];
	Point		ptPubKey;

	uint8		bSignValue[SIGN_LEN];
	unsigned int array_x[PARABUFFER];
	unsigned int array_y[PARABUFFER];


	memcpy(tempPubKey, cerPubKey->data, cerPubKey->length);

	ptPubKey.x = array_x;
	ptPubKey.y	= array_y;

	OctetStringToPubKey(tempPubKey, PUBKEY_LEN, &ptPubKey);

	if (pSignData->length != SIGN_LEN)
	{
		return FALSE;
	}
	else
	{
		memcpy(bSignValue, pSignData->data, pSignData->length);
		bVerify = Verify_With_Public_Key(buffer, bufflen, bSignValue,
		pSignData->length, ptPubKey);
	}

	return bVerify;

}


static boolean  VerifyPacketHMACData(uint8 * buffer, uint16 bufflen,
		uint8 *pMAK, uint8 *pHMAC)
{
	boolean bVerify = FALSE;
	uint8	bWAIHMAC[HMAC_LEN];

	int	nLenHMAC = 20;

	int nReturnLen = wapi_hmac_sha256(
		(uint8 *)buffer,
		bufflen,
		pMAK,
		16,
		bWAIHMAC,
		nLenHMAC);

	if (nReturnLen == 0)
	{
		return FALSE;
	}
	else
	{
		if (memcmp(bWAIHMAC, pHMAC, HMAC_LEN) == 0)
		{
			bVerify = TRUE;
		}
		else
			bVerify = FALSE;
	}

	return bVerify;

}


static boolean  CalculateBKFromXYPN1N2(const uint8 * Y, const byte_data * xP,
	const uint8 * Nae, const uint8 * Nasue, uint8 *pBK, uint8 *pNnext)
{
	uint8		tempPubKey[PUBKEY_LEN];
	Point		ptPubKey;
	unsigned int  tempY[6];
	int		lenTempY = 6;

	unsigned int  lenPubKeyX = PUBKEY_LEN / 2;
	uint8		bPubKeyX[PUBKEY_LEN / 2];
	uint8		bKeyBuffer[RAND_LEN * 2 + BKSA_SHA_STR_LEN];
	uint8		bKeyOut[BK_EXPANSION_LEN];

	CONTX		contx;
	unsigned int array_x[PARABUFFER];
	unsigned int array_y[PARABUFFER];


	memcpy(tempPubKey, xP->data + 1, xP->length - 1);

	ptPubKey.x = array_x;
	ptPubKey.y = array_y;

	OctetStringToPubKey(tempPubKey, PUBKEY_LEN, &ptPubKey);
	OctetStringToPriKey(Y, SECKEY_LEN, (unsigned int *)tempY, &lenTempY);

    if (KTimesPoint((unsigned int*)tempY,
		&lenTempY,
		&ptPubKey,
		WAPI_ECDH_KEY_LEN,
		&ptPubKey,
		WAPI_ECDH_KEY_LEN) == 0)
    {
		return FALSE;
    }

	memcpy(bKeyBuffer, Nae, RAND_LEN);
	memcpy(bKeyBuffer + RAND_LEN, Nasue, RAND_LEN);
	memcpy(bKeyBuffer + 2 * RAND_LEN, BKSA_SHA_STR, BKSA_SHA_STR_LEN);

	PriKeyToOctetString(ptPubKey.x,
		lenTempY,
		lenPubKeyX,
		&lenPubKeyX,
		bPubKeyX
		);

	KD_hmac_sha256(bKeyBuffer,
		sizeof(bKeyBuffer),
		bPubKeyX,
		lenPubKeyX,
		bKeyOut,
		BK_EXPANSION_LEN);

	//get BK
	memcpy(pBK, bKeyOut, 16);

	contx.buff = &bKeyOut[16];
	contx.length = BK_EXPANSION_LEN - 16;
	if (mhash_sha256(&contx,
		1,
		pNnext,
		BK_EXPANSION_LEN - 16) == 0)
	{
	return FALSE;
	}
	return TRUE;
}


static boolean CalculateSignDataFromSourceData(const uint8 * buffer,
	const uint16 bufflen, const byte_data * staSecKey, uint8 *pSignData)
{
	boolean  bSignOK = FALSE;

	unsigned int  piSecKey[6];
	int  lenSecKey = 6;
	int nSignLen;
	if (staSecKey->length != 24)
		return FALSE;
	else
	{
		OctetStringToPriKey(staSecKey->data,
			staSecKey->length,
			(unsigned int *)piSecKey,
			&lenSecKey);

		nSignLen = Sign_With_Private_Key(pSignData,
			buffer,
			bufflen,
			(unsigned int *)piSecKey,
			lenSecKey);

	    if ( nSignLen == 0)
		{
			return FALSE;
		}

		bSignOK = TRUE;
	}

	return bSignOK;

}


static boolean  CalculateHMACData(uint8 * buffer, uint16 bufflen,
	uint8 *pMAK, uint8 *pHMAC)
{
	boolean bCalcHMAC = FALSE;

	int  nLenHMAC = 20;

	int nReturnLen = wapi_hmac_sha256(
		buffer,
		bufflen,
		pMAK,
		16,
		pHMAC,
		nLenHMAC);

	if (nReturnLen == 0)
	{
		return FALSE;
	}
	else
	{
		if (nLenHMAC == HMAC_LEN)
		    bCalcHMAC = TRUE;
	}

	return bCalcHMAC;
}
eWAIPackType  GetWAPIPacketType(const uint8 * buffer, uint16 bufflen)
{
	eWAIPackType  nWAPIPacketType = ePACKTYPE_WAPI_PROTO_UNKNOWN;
	packet_head   wapi_hdr;

	if ((bufflen) > sizeof(packet_head))
	{
		c_unpack_packet_head(&wapi_hdr, buffer , bufflen);
	}
	else
	{
		return ePACKTYPE_WAPI_PROTO_UNKNOWN;
	}

	if ( (wapi_hdr.version != 0x0001) || (wapi_hdr.type != 0x01)
				||(wapi_hdr.reserved != 0x0000 ) )
	{
		return ePACKTYPE_WAPI_PROTO_UNKNOWN;
	}

	switch (wapi_hdr.subtype)
	{
		case 1:
			nWAPIPacketType = ePACKTYPE_WAPI_PROTO_PREAUTH;
			break;

		case 2:
			nWAPIPacketType = ePACKTYPE_WAPI_PROTO_STAKEY_REQU;
			break;

		case 3:
			nWAPIPacketType = ePACKTYPE_WAPI_PROTO_AUTH_ACTIVE;
			break;

		case 4:
			nWAPIPacketType = ePACKTYPE_WAPI_PROTO_ACCESS_AUTH_REQU;
			break;

		case 5:
			nWAPIPacketType = ePACKTYPE_WAPI_PROTO_ACCESS_AUTH_RESP;
			break;

		case 8:
			nWAPIPacketType = ePACKTYPE_WAPI_PROTO_SSKEY_NEG_REQU;
			break;

		case 9:
			nWAPIPacketType = ePACKTYPE_WAPI_PROTO_SSKEY_NEG_RESP;
			break;

		case 10:
			nWAPIPacketType = ePACKTYPE_WAPI_PROTO_SSKEY_NEG_ACK;
			break;

		case 11:
			nWAPIPacketType = ePACKTYPE_WAPI_PROTO_GKEY_SET_REQU;
			break;

		case 12:
			nWAPIPacketType = ePACKTYPE_WAPI_PROTO_GKEY_SET_RESP;
			break;

		default:
			return ePACKTYPE_WAPI_PROTO_UNKNOWN;
	}

	return nWAPIPacketType;

}



static boolean  IsWholeWAPIPacket(const uint8 * buffer, uint16 bufflen,
			uint8 *sourcedatabufferWLAN, int *nPacketLenWLAN)
{
	boolean bWholeWAPIPacket = FALSE;
	uint8 bIDTemp;
	uint8 bFragmentTemp;
	uint8 bPacketNumberTemp[2];

	memcpy(&bIDTemp, buffer + 11, 1);
	memcpy(&bFragmentTemp, buffer + 10, 1);
	memcpy(bPacketNumberTemp, buffer + 8, 2);

	if (nPacketSubTypeWLAN == GetWAPIPacketType(buffer, bufflen))
	{
		if (memcmp(bPacketNumberTemp, bPacketNumberWLAN, 2) == 0)
		{
			if (bIDTemp == 0)
			{
				if (bFragmentTemp == 0)
				{
					nPacketSubTypeWLAN = GetWAPIPacketType(
								buffer, bufflen);
					memcpy(bPacketNumberWLAN,
						bPacketNumberTemp, 2);

					memset(sourcedatabufferWLAN, 0,
						bufflen);
					memcpy(sourcedatabufferWLAN, buffer,
						 bufflen);

					*nPacketLenWLAN = bufflen;
					bFragmentNumberWLAN = bFragmentTemp;
					nCurrPackLenWLAN = 0;

					bWholeWAPIPacket = TRUE;
				}
				else
				{
					if (bFragmentTemp > 0)
					{
						if (bFragmentTemp ==
							bFragmentNumberWLAN + 1)
						{
							memcpy(sourcedatabufferWLAN + nCurrPackLenWLAN,
							buffer + WAPI_HEADER_LEN,
							bufflen - WAPI_HEADER_LEN);
							nCurrPackLenWLAN += bufflen - WAPI_HEADER_LEN;
							*nPacketLenWLAN = nCurrPackLenWLAN ;
							 /* since this is the last fragment*/
							nCurrPackLenWLAN = 0;

							bWholeWAPIPacket = TRUE;

							wpa_printf(MSG_DEBUG,
							"WAPI: Recvd Frag len = %d frag no. = %d",
							*nPacketLenWLAN, bFragmentTemp);
						}
						else
						{
							// packet is lost
							memset(sourcedatabufferWLAN, 0, nCurrPackLenWLAN);

							*nPacketLenWLAN = 0;
							bFragmentNumberWLAN = 0;
							nCurrPackLenWLAN = 0;

							bWholeWAPIPacket = FALSE;
						}
					}

				}

			}
			else
			{
				if ( bFragmentTemp == 0)	//first fragment retranmission
				{
					nPacketSubTypeWLAN = GetWAPIPacketType(
								buffer, bufflen);
					memcpy(bPacketNumberWLAN,
					bPacketNumberTemp, 2);

					memset(sourcedatabufferWLAN, 0,
						bufflen);
					memcpy(sourcedatabufferWLAN + 0,
						buffer, bufflen);

					nCurrPackLenWLAN = bufflen;
					*nPacketLenWLAN = nCurrPackLenWLAN ;
					bFragmentNumberWLAN = bFragmentTemp;

					bWholeWAPIPacket = FALSE;
				}
				else
				{
					if (bFragmentTemp == bFragmentNumberWLAN + 1)
					{

						memcpy(sourcedatabufferWLAN
						+ nCurrPackLenWLAN, buffer
						+ WAPI_HEADER_LEN, bufflen
						- WAPI_HEADER_LEN);

						nCurrPackLenWLAN += bufflen
						- WAPI_HEADER_LEN;
						*nPacketLenWLAN =
						nCurrPackLenWLAN ;
						bFragmentNumberWLAN =
						bFragmentTemp;

						wpa_printf(MSG_DEBUG,
						"WAPI: Recvd Frag len ="
						" %d frag no. = %d",
						*nPacketLenWLAN, bFragmentTemp);

						bWholeWAPIPacket = FALSE;

					}
					else
					{
						memset(sourcedatabufferWLAN, 0,
						nCurrPackLenWLAN);
						*nPacketLenWLAN = 0;
						bFragmentNumberWLAN = 0;
						nCurrPackLenWLAN = 0;
			/* discard all the fragments that received so far;
			since the buffer is reset to zero,
			* GetWAPIPacketType in next execution shall
			take care of it;*/
						bWholeWAPIPacket = TRUE;
					}
				}
			}
		}
		else
		{	/*we come here when STA acks a frame & drops it;
			 and then AP transmits again (different seq no) -
			no frags involved */

			nPacketSubTypeWLAN = GetWAPIPacketType(buffer, bufflen);
			memcpy(bPacketNumberWLAN, bPacketNumberTemp, 2);
			memset(sourcedatabufferWLAN, 0, bufflen);

			memcpy(sourcedatabufferWLAN, buffer, bufflen);
			nCurrPackLenWLAN = bufflen;

			*nPacketLenWLAN = nCurrPackLenWLAN;

			bFragmentNumberWLAN = bFragmentTemp;

			//only one packet
			if (bIDTemp == 0)
			{
				nCurrPackLenWLAN = 0;
				bWholeWAPIPacket = TRUE;
			}
		}
	}
	else
	{
		nPacketSubTypeWLAN = GetWAPIPacketType(buffer, bufflen);
		memcpy(bPacketNumberWLAN, bPacketNumberTemp, 2);
		bFragmentNumberWLAN = bFragmentTemp;

		memcpy(sourcedatabufferWLAN + *nPacketLenWLAN, buffer, bufflen);
		nCurrPackLenWLAN = bufflen;
		*nPacketLenWLAN = nCurrPackLenWLAN;

		if (bIDTemp == 0)
		{
			if (bFragmentTemp > 0)
			{
				memset(sourcedatabufferWLAN, 0,
				nCurrPackLenWLAN);
				*nPacketLenWLAN = 0;
				/*the first packet shall not have more
				frag flag = 0 & frag.seq.no >0;
				it mean that we lost a fragment the first
				 fragment; hence discard*/
				nCurrPackLenWLAN = 0;

				bWholeWAPIPacket = FALSE;
			}
			else
			{
				nCurrPackLenWLAN = 0;
				bWholeWAPIPacket = TRUE;
			}
		}
		else
		{
			wpa_printf(MSG_DEBUG,
			"Received First Fragment length = %d", *nPacketLenWLAN);

			bWholeWAPIPacket = FALSE;
		}
	}

	return bWholeWAPIPacket;
}


static boolean WAPIProtocolSend88B4Packet(const uint8* buffer, uint16 bufflen)
{

	wlan_wapi_iface_return_status_enum_type ret;

	ret = wlan_wapi_iface_send_pkt(g_wapi_iface_handle,
					WLAN_WAPI_IFACE_WAI_ETHERTYPE_TYPE,
					g_connect_data.bssid, bufflen,
					(uint8 *)buffer);

	if( ret != WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS )
	{
		return FALSE;
	}

	return TRUE;
}



static void Connect_event_func(wlan_wapi_iface_event_type *wlan_ev,
				void *user_data_ptr)
{
	char *file_path;
	uint8 cert_type;
	wlan_wapi_iface_auth_result_type res;
	int ret_status = eWAI_CERT_CERTIFICATE_FORMAT_ERROR;

	if( g_eWaiStatus == WAIPS_NONE )
	{
		wpa_printf(MSG_ERROR,
		"WAPI: Got Connect_event in %d state\n",g_eWaiStatus);
	}
	else
	{
		g_connect_data = wlan_ev->event_info.connect_ev;

		memcpy(g_bAPBSSIDMac, g_connect_data.bssid,
			WLAN_WAPI_IFACE_MAC_ADDR_LEN);

		memcpy(g_bSTAMac, g_connect_data.sta_mac_address,
		WLAN_WAPI_IFACE_MAC_ADDR_LEN);
		memcpy(g_ieAssocAp, g_connect_data.beacon_probe_wapi_ie.ie_data,
		g_connect_data.beacon_probe_wapi_ie.ie_len);

		g_pStaCertificateParam = &g_StaCertificateParam;

		switch( g_connect_data.config_params.auth_type )
		{
		case WLAN_WAPI_IFACE_AUTH_TYPE_OPEN:
		{
			wpa_printf(MSG_ERROR,
				"WAPI: Connect_event_func auth_type success \n");

			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_SUCCESS;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_UNKNOWN;
			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);
		}
		break;

		case WLAN_WAPI_IFACE_AUTH_TYPE_PSK:
			g_eWaiStatus = WAPIS_WAI_BEGIN;
			break;

		case WLAN_WAPI_IFACE_AUTH_TYPE_CERT:
		{
			ret_status = wapi_load_certificates();
			wpa_printf(MSG_INFO, "[%s] Load Certificates"
			" Ret. Code:%d",__func__,ret_status);

			if(eWAI_CERT_NO_ERROR == ret_status)
			{
				res.result =
				WLAN_WAPI_IFACE_AUTH_RESULT_SUCCESS;
				res.failure_reason =
				WLAN_WAPI_IFACE_AUTH_FAIL_REASON_UNKNOWN;

				g_eWaiStatus = WAPIS_WAI_BEGIN;

			}
			else
			{
				wpa_printf(MSG_ERROR,
				"WAPI: Connect_event_func rc = %d\n",
				ret_status);
				res.result =
				WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
				res.failure_reason =
				WLAN_WAPI_IFACE_AUTH_FAIL_REASON_UNKNOWN;
				wlan_wapi_iface_auth_result_ind(
						g_wapi_iface_handle, res);

			}
		}
			break;

		default:
		{
			wpa_printf(MSG_ERROR, "WAPI: Connect_event_func"
						" auth_type error \n");

			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_UNKNOWN;

			wlan_wapi_iface_auth_result_ind(
				g_wapi_iface_handle, res);
		}
			break;
		}
	}

	return;

}


void wlan_wapi_iface_receive_pkt_cback(uint32 length,uint8 *pkt,
					void *user_data_ptr)
{

	wlan_wapi_iface_auth_result_type res;

	uint8* sourcedatabufferWLAN = NULL;
	int nPacketLenWLAN = 0;
	uint32 nReturnWAIProcess = 0;

	sourcedatabufferWLAN = senddatabuffer+TX_DATA_BUFF_SIZE;

	pIdentitySTAae	= (identity*)(sourcedatabufferWLAN + RX_DATA_BUFF_SIZE);
	pCerSTAae = (certificate*)(pIdentitySTAae+1);

	if( (g_eWaiStatus == WAIPS_NONE) || ( g_eWaiStatus == WAIPS_IDEL ) )
	{
		wpa_printf(MSG_INFO,"WAPI: WAI SM not intialized; "
				"current state = %d\n",g_eWaiStatus);

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);
	}
	else
	{
		if (IsWholeWAPIPacket((const uint8*)pkt, (uint16)length,
					sourcedatabufferWLAN, &nPacketLenWLAN))
		{
			nReturnWAIProcess = ProcessWAPIProtocolAccessAP(
					sourcedatabufferWLAN, nPacketLenWLAN);

			if (nReturnWAIProcess != 0)
			{
				wpa_printf(MSG_INFO,
				"%s WAPI: WAI procedure failed rc = %d",
				__func__, nReturnWAIProcess);
				g_eWaiStatus = WAIPS_IDEL;
			}
		}
	}

	return;

}

void wlan_wapi_iface_event_cback(wlan_wapi_iface_event_type *wlan_ev,
							void *user_data_ptr)
{
	wlan_wapi_iface_cmd_type	cmd;
	switch( wlan_ev->event_id)
	{
	case WLAN_WAPI_IFACE_EV_CONNECT:
		Connect_event_func(wlan_ev,user_data_ptr);
		break;

	case WLAN_WAPI_IFACE_EV_DISCONNECT:
		{
			wpa_printf(MSG_DEBUG, "%s WAPI: Got Disconnect Event",
					__func__);

			g_eWaiStatus = WAIPS_IDEL;

			if ( wlan_wapi_iface_get_timer(nTmAccessAuthRequ) > 0)
			{
				wlan_wapi_iface_stop_timer(nTmAccessAuthRequ);
			}

			if ( wlan_wapi_iface_get_timer(nTmSessionNegResp) > 0)
			{
				wlan_wapi_iface_stop_timer(nTmSessionNegResp);
			}
		}
		break;

	case WLAN_WAPI_IFACE_EV_EXTENDED:
		wpa_printf(WLAN_WAPI_IFACE_PRINT_PRI_HIGH,
				"WAPI: Got Extended Event\n");
		break;

	default:
		wpa_printf(WLAN_WAPI_IFACE_PRINT_PRI_HIGH,
				"WAPI: Got Unknown Event\n");
		break;
	}

	return;

}

uint32  ProcessWAPIProtocolAccessAP(const uint8 * buffer, uint16 bufflen)
{
	int res =0;
	eWAIPackType nPacketType = GetWAPIPacketType(buffer, bufflen);

	wpa_printf(MSG_INFO,"%s WAPI: WAPI packet type %d recvd",
						__func__, nPacketType);

	switch (nPacketType)
	{
		case ePACKTYPE_WAPI_PROTO_PREAUTH:
			return 0;

		case ePACKTYPE_WAPI_PROTO_STAKEY_REQU:
			return 0;

		case ePACKTYPE_WAPI_PROTO_AUTH_ACTIVE:
			wapi_supplicant_key_negotiation_state_report(
							WPA_4WAY_HANDSHAKE);
			res = ProcessWAPIProtocolAuthActive(buffer, bufflen);
			return res;
		case ePACKTYPE_WAPI_PROTO_ACCESS_AUTH_REQU:
			return 0;

		case ePACKTYPE_WAPI_PROTO_ACCESS_AUTH_RESP:
			//send wpa_supplicant handshake
			res  =  ProcessWAPIProtocolAccessAuthResp(buffer,
								bufflen);
			return res;

		case ePACKTYPE_WAPI_PROTO_SSKEY_NEG_REQU:
			//send wpa_supplicant handshake
			if(wapi_supplicant_get_state() < WPA_COMPLETED ||
			   wapi_supplicant_get_state() != WPA_COMPLETED) {
				/*for Reky case if state is chaged, UI doesn't get
				updated properly, so donot change state*/
				wapi_supplicant_key_negotiation_state_report(
							WPA_4WAY_HANDSHAKE);
			}
			res = ProcessWAPIProtocolSessNegRequ(buffer, bufflen);
			return res;
		case ePACKTYPE_WAPI_PROTO_SSKEY_NEG_RESP:
			return 0;

		case ePACKTYPE_WAPI_PROTO_SSKEY_NEG_ACK:
			 res = ProcessWAPIProtocolSessNegAck(buffer, bufflen);
			 return res;
		case ePACKTYPE_WAPI_PROTO_GKEY_SET_REQU:
			if(g_eWaiStatus < WAIPS_GRP_NOTIFY_OK){
				wapi_supplicant_key_negotiation_state_report(
							WPA_GROUP_HANDSHAKE);
			}
			res = ProcessWAPIProtocolGroupKeyNotice(buffer, bufflen);
			if(res == 0) {
				if(wapi_supplicant_get_state() != WPA_COMPLETED) {
					wapi_supplicant_key_negotiation_state_report(WPA_COMPLETED);
				}
			}
			return res;
		case ePACKTYPE_WAPI_PROTO_GKEY_SET_RESP:
			return 0;

		default:
			return 0;
	}
}

uint32  ProcessWAPIProtocolAuthActive(const uint8 * buffer, uint16 bufflen)
{
	wlan_wapi_iface_auth_result_type res;

	Point	pntPubKey;
	unsigned int tempX[6];
	int	lenTempX	= 6;
	uint8	tempPubKey[PUBKEY_LEN] = {0};

	/*temp public key 's first byte must is 0x004*/
	uint8	pubKey[PUBKEY_LEN + 1] = {0x04,};
	uint8   bSignData[SIGN_LEN];

	short	usReturnUnPackRes = 0;
	uint8	bBKRefrash	= 0;
	identity sIdentity;
	uint8	bHeadX[16]	= {0};
	uint8	bPadingX[16] = {0};
	unsigned long * r	= NULL;
	unsigned long * rp	= NULL;
	unsigned int array_x[PARABUFFER];
	unsigned int array_y[PARABUFFER];
	unsigned long * rr = NULL;
	uint8	*bTempDataBuffer	= NULL;
	uint16	nTempDataBufferLen	= 0;

	byte_data bIssureNameAS;
	byte_data bIssureNameEntry;
	byte_data bSign;


	if (g_eWaiStatus != WAPIS_WAI_BEGIN && g_eWaiStatus != WAIPS_AUTHING)
	{
		wpa_printf(MSG_ERROR,
			  "%s WAPI: Auth Activation recvd WAI state: %d\n",
			  __func__,g_eWaiStatus);
		return wapi_err_ProcessStatues_wai_not_begin;
	}
	else if(g_eWaiStatus == WAIPS_AUTHING)
	{
		return 0;
	}


	memset(&bIssureNameAS,0,sizeof(bIssureNameAS));
	memset(&bIssureNameEntry,0,sizeof(bIssureNameEntry));
	memset(&bSign,0,sizeof(bSign));
	memset(&sIdentity,0,sizeof(sIdentity));

	memset(bSignData, 0, SIGN_LEN);
	memset(&AuthActivePacket, 0, sizeof(AuthActivePacket));

	usReturnUnPackRes = unpack_auth_active(&AuthActivePacket, buffer,
						bufflen);

	if (usReturnUnPackRes == PACK_ERROR)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR, "WAPI: Auth Activation unpack failed");

		return wapi_err_UnPackAuthActive;
	}

	wlan_wapi_iface_status_ind(g_wapi_iface_handle,
	WLAN_WAPI_IFACE_WAI_STATUS_EV_AUTH_START);

	bBKRefrash = AuthActivePacket.flag & 1;

	if (bBKRefrash == 1)
	{
		if (memcmp(AuthActivePacket.authidentify, bLastAuthID,
				RAND_LEN) != 0)
		{
			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);
			wpa_printf(MSG_ERROR, "%s WAPI: authidentify mismatch",
				__func__);
			return wapi_err_STAaeIdentityMisMatch;
		}
	}

	memset(&sIdentity, 0, sizeof(sIdentity));

	if(get_identity_from_certificate(&g_pStaCertificateParam->cerASUSTAasue,
				&sIdentity) != 0)
	{
		wpa_printf(MSG_ERROR, "%s WAPI: get_identity_from_certificate"
				" fail",__func__);

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_CERT_INVALID;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_SearchCertificateIdentity;
	}

	if (memcmp(&AuthActivePacket.localasuidentity, &sIdentity,
		sizeof(AuthActivePacket.localasuidentity)) == 0)
	{
	}
	else
	{
		wpa_printf(MSG_ERROR, "%s WAPI: localasuidentity and sIdentity"
				" mismatch",__func__);

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_CERT_INVALID;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

	}


	if(get_issurenameentry_from_certificate(
	&g_pStaCertificateParam->cerASUSTAasue, &bIssureNameAS) != 0)
	{
		wpa_printf(MSG_ERROR,
		"%s WAPI: get_issurenameentry_from_certificate failed",
		__func__);

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_CERT_INVALID;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_SearchCertificateIssureName;
	}


	if(get_issurenameentry_from_certificate(
		&g_pStaCertificateParam->cerSTAasue, &bIssureNameEntry) != 0)
	{
		wpa_printf(MSG_ERROR,
		"%s WAPI: get_issurenameentry_from_certificate failed",
		__func__);

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_CERT_INVALID;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_SearchCertificateIssureName;
	}

	if (memcmp(&bIssureNameAS, &bIssureNameEntry,
		sizeof(bIssureNameEntry)) != 0)
	{
		wpa_printf(MSG_ERROR, "%s WAPI: bIssureNameAS and"
				"bIssureNameEntry are not same", __func__);

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason = WLAN_WAPI_IFACE_AUTH_FAIL_REASON_CERT_INVALID;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_NoUseASCertificate;
	}

	memcpy(pCerSTAae, &AuthActivePacket.certificatestaae,
			sizeof(AuthActivePacket.certificatestaae));

	memset(pIdentitySTAae, 0, sizeof(identity));

	if (get_identity_from_certificate(&AuthActivePacket.certificatestaae,
			pIdentitySTAae) == PACK_ERROR)
	{
		wpa_printf(MSG_ERROR, "%s WAPI: get_identity_from_certificate"
			" failed",__func__);

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_CERT_INVALID;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_OtherFaild;
	}


	//generate temp private key
	r = (unsigned long *)bHeadX;
	generate_random( r );
	rp = (unsigned long *)bPadingX;
	generate_random( rp );
	memcpy(bx, bHeadX, 16);
	memcpy(bx + 16, bPadingX, 8);

	memset(tempX, 0, sizeof(tempX));

	//must && 0xbc !
	bx[0] &= 0xbc;
	OctetStringToPriKey(bx,
		SECKEY_LEN,
		(unsigned int*)tempX,
		&lenTempX);

	pntPubKey.x = array_x;
	pntPubKey.y = array_y;

	if ( Generate_PubKey((unsigned int*)tempX, lenTempX, &pntPubKey)== 0 )
	{
		wpa_printf(MSG_ERROR, "%s WAPI: Generate_PubKey failed",
				__func__);

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PSK_INVALID;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_OtherFaild;
	}

	//generate temp pubkey
	lenTempX = sizeof(pubKey) - 1;
	PubKeyToOctetString(&pntPubKey, lenTempX, (unsigned int * ) &lenTempX,
			tempPubKey);
	memcpy(&pubKey[1], tempPubKey,	PUBKEY_LEN);

	bxP.length = PUBKEY_LEN + 1;
	memcpy(bxP.data, pubKey, PUBKEY_LEN + 1);

	rr = (unsigned long *)bAsueChallenge;
	generate_random( rr );
	rr = (unsigned long *)bAsueChallenge + 4;
	generate_random( rr );

	//set  AccessAuthRequPacket
	AccessAuthRequPacket.flag = AuthActivePacket.flag;

	if (bBKRefrash == 0)
	{
		AccessAuthRequPacket.flag |= 4;
	}

	memcpy(AccessAuthRequPacket.authidentify, AuthActivePacket.authidentify,
		RAND_LEN);
	memcpy(AccessAuthRequPacket.asuechallenge, bAsueChallenge, RAND_LEN);
	memcpy(&AccessAuthRequPacket.asuekeydata, &bxP, sizeof(bxP));
	memcpy(&AccessAuthRequPacket.staasueidentity, pIdentitySTAae,
		sizeof(identity));
	memcpy(&AccessAuthRequPacket.certificatestaasue,
		&g_pStaCertificateParam->cerSTAasue,
		sizeof(g_pStaCertificateParam->cerSTAasue));
	memcpy(&AccessAuthRequPacket.ecdhparam, &AuthActivePacket.ecdhparam,
		sizeof(AuthActivePacket.ecdhparam));

	bTempDataBuffer = senddatabuffer;

	memset(bTempDataBuffer, 0, BUFF_SPLIT_SIZE);

	nTempDataBufferLen = 0;

	nTempDataBufferLen = pack_access_auth_requ_to_buffer(
		&AccessAuthRequPacket, bTempDataBuffer, BUFF_SPLIT_SIZE);

	if ( nTempDataBufferLen == PACK_ERROR)
	{
		wpa_printf(MSG_ERROR, "%s WAPI: Pack Access Auth Req failed",
				__func__);

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_OtherFaild;
	}


	if (!CalculateSignDataFromSourceData(bTempDataBuffer,
	nTempDataBufferLen, &g_pStaCertificateParam->staSecKey, bSignData))
	{
		wpa_printf(MSG_ERROR,
		"%s WAPI: CalculateSignDataFromSourceData failed",__func__);

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PSK_INVALID;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_OtherFaild;
	}


	bSign.length = SIGN_LEN;
	memcpy(&bSign.data, bSignData, SIGN_LEN);

	build_sign_attribute_from_signdata(
		&g_pStaCertificateParam->cerSTAasue, &bSign,
		&AccessAuthRequPacket.asuesign);

	memset(bTempDataBuffer, 0, BUFF_SPLIT_SIZE);

	nTempDataBufferLen = pack_access_auth_requ(&AccessAuthRequPacket,
				bTempDataBuffer, BUFF_SPLIT_SIZE);

	if ( nTempDataBufferLen == PACK_ERROR)
	{
		wpa_printf(MSG_ERROR, "%s WAPI: Pack Access Auth req failed",
				__func__);

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_UNKNOWN;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_OtherFaild;
	}

	nSendPacketLen = nTempDataBufferLen;

	if (WAPIProtocolSend88B4Packet(senddatabuffer, nSendPacketLen))
	{
		wpa_printf(MSG_INFO, " %s WAPI: Send Access Auth req success",
				__func__);
		g_eWaiStatus = WAIPS_AUTHING;
		wlan_wapi_iface_start_timer(nTmAccessAuthRequ,
					ACCESSAUTHREQU_TIMEOUT);
		return 0;
	}
	else
	{
		wpa_printf(MSG_ERROR, "WAPI: Send Access Auth req failed");

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_UNKNOWN;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_SendAccessAuthRequ;
	}
}


uint32  ProcessWAPIProtocolAccessAuthResp(const uint8 * buffer, uint16 bufflen)
{

	wlan_wapi_iface_auth_result_type res;

	identity	identitySTAasue;
	uint8		bBit0, bBit1;
	uint8		PubKeySTAae[PUBKEY_LEN] = {0};
	short		usReturnUnPackRes	= 0;
	byte_data	bdPubKey;
	unsigned short lenAESignAttribute;
	byte_data	bPubKey;


	uint8	*bTempDataBuffer = NULL;
	uint16	nTempDataBufferLen = 0;

	if(g_eWaiStatus == WAIPS_AUTH_OK)
	{
		wpa_printf(MSG_INFO, "%s WAPI: Access Auth already completed",
				__func__);
		wpa_printf(MSG_INFO, "Discarding received frame. "
				"Current State:%d",g_eWaiStatus);
		return 0;
	}

	if (g_eWaiStatus != WAIPS_AUTHING)
	{
		wpa_printf(MSG_INFO,"%s WAPI: Access Auth Resp"
			" recvd in %d state",__func__,g_eWaiStatus);
		return wapi_err_OtherFaild;
	}

	memset(&identitySTAasue,0,sizeof(identitySTAasue));
	memset(&bdPubKey,0,sizeof(bdPubKey));
	memset(&bPubKey,0,sizeof(bPubKey));
	memset(&AccessAuthRespPacket, 0, sizeof(AccessAuthRespPacket));

	usReturnUnPackRes = unpack_access_auth_resp(
			&AccessAuthRespPacket, buffer, bufflen);

	if (usReturnUnPackRes == PACK_ERROR)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR, "WAPI: Access Auth Resp Unpack failed");

		return wapi_err_UnPackAccessAuthResp;

	}

	wlan_wapi_iface_stop_timer(nTmAccessAuthRequ);

	if (memcmp(&AccessAuthRespPacket.staaeidentity, pIdentitySTAae,
				pIdentitySTAae->identity_length + 2 + 2) != 0)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
		"WAPI: Access Auth Resp staaeidentity mismatch");
		return wapi_err_STAaeIdentityMisMatch;
	}


	if (get_identity_from_certificate(
	&AccessAuthRequPacket.certificatestaasue, &identitySTAasue) != 0)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR, "WAPI: Access Auth Resp"
			" get_identity_from_certificate failed");
		return wapi_err_OtherFaild;
	}


	if (memcmp(&AccessAuthRespPacket.staasueidentity,
		&identitySTAasue, identitySTAasue.identity_length + 2 + 2) != 0)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
		"WAPI: Access Auth Resp staasueidentity mismatch");
		return wapi_err_STAasueIdentityMisMatch;
	}

	bBit0 = AccessAuthRespPacket.flag & 1;
	bBit1 = (AccessAuthRespPacket.flag & 2) >> 1;

	if ((AccessAuthRequPacket.flag & 1) != bBit0)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,"WAPI: Access Auth Resp -"
			" FLAG of BK refresh not matched");
		return wapi_err_FLAGRefreshBKMisMatch;
	}

	if (((AccessAuthRequPacket.flag & 2) >> 1) != bBit1)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR, "WAPI: Access Auth Resp - "
			"Pre-auth FLAG of BK refresh not matched");
		return wapi_err_FLAGPreAuthMisMatch;
	}


	if (memcmp(AccessAuthRespPacket.asuechallenge,
		AccessAuthRequPacket.asuechallenge, RAND_LEN) != 0)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
		"WAPI: Access Auth Resp - ASUE Challenge not matched");
		return wapi_err_ASUEChallengeMisMatch;
	}


	if (memcmp(&AccessAuthRespPacket.asuekeydata,
		&AccessAuthRequPacket.asuekeydata,
		AccessAuthRequPacket.asuekeydata.length + 1) != 0)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PSK_INVALID;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
			"WAPI: Access Auth Resp - asuekeydata mismatch");
		return wapi_err_ASUEKeyDataMisMatch;
	}

	if (get_pubkeyvalue_from_certificate(pCerSTAae, &bdPubKey) != 0)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PSK_INVALID;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR, "WAPI: Access Auth Resp - Get Public "
					"Key from STAae cert error");
		return wapi_err_OtherFaild;
	}

	memcpy(PubKeySTAae, bdPubKey.data, bdPubKey.length);

	lenAESignAttribute = AccessAuthRespPacket.aesign.length + 2 + 1;

	bTempDataBuffer = senddatabuffer;
	nTempDataBufferLen = 0;
	nTempDataBufferLen = bufflen - WAPI_HEADER_LEN - lenAESignAttribute;

	memset(bTempDataBuffer, 0, nTempDataBufferLen);
	memcpy(bTempDataBuffer, buffer + WAPI_HEADER_LEN, nTempDataBufferLen);

	if (!VerifyPacketSignData(bTempDataBuffer, nTempDataBufferLen,
			&AccessAuthRespPacket.aesign.sign, &bdPubKey))
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR, "WAPI: Access Auth Resp -"
				" VerifyPacketSignData error");
		return wapi_err_VerifyAESignFailure;
	}


	if (AccessAuthRespPacket.accessresult != 0)
	{
		wpa_printf(MSG_ERROR, "WAPI: Access Auth Resp -"
			" verify access result failed");

		if (WAPISendDisconnectEv() !=
			WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS )
		{
			wpa_printf(MSG_ERROR, "WAPISendDisconnectEv failed");
		}

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_VerifyAccessResultFailure;
	}


	if (((AccessAuthRespPacket.flag & 8) >> 3) == 1)
	{
		nTempDataBufferLen = pack_certificate_vaild_result(
					&AccessAuthRespPacket.cervalidresult,
					bTempDataBuffer, BUFF_SPLIT_SIZE);

		if (nTempDataBufferLen == PACK_ERROR)
		{
			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);

			wpa_printf(MSG_ERROR,"WAPI: Access Auth Resp - "
					"Pack cert auth result failed");
			return wapi_err_OtherFaild;
		}


		if ( get_pubkeyvalue_from_certificate(
			&g_pStaCertificateParam->cerASUSTAasue, &bPubKey) != 0)
		{
			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PSK_INVALID;

			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);

			wpa_printf(MSG_ERROR,"WAPI: Access Auth Resp - "
			"Get Public Key from AS cert of ASUE failed");
			return wapi_err_OtherFaild;

		}

		memcpy(PubKeySTAae, bPubKey.data, bPubKey.length);

		if (AccessAuthRespPacket.asueassign.type != 1)
		{
			if (! VerifyPacketSignData(bTempDataBuffer,
				nTempDataBufferLen,
				&AccessAuthRespPacket.aeassign.sign,
				&bPubKey)
				)
			{
				res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
				res.failure_reason =
				WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

				wlan_wapi_iface_auth_result_ind(
					g_wapi_iface_handle, res);

				wpa_printf(MSG_ERROR,"WAPI: Access Auth Resp -"
				" verify sign data of server trusted with "
				"ASUE error");
				return wapi_err_VerifyASUEASUSignFailure;
			}
		}
		else
		{
			if ( !VerifyPacketSignData(bTempDataBuffer,
				nTempDataBufferLen,
				&AccessAuthRespPacket.asueassign.sign,
				&bPubKey)
				)
			{
				res.result =
				WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
				res.failure_reason =
				WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

				wlan_wapi_iface_auth_result_ind(
					g_wapi_iface_handle, res);

				wpa_printf(MSG_ERROR,"WAPI: Access Auth Resp -"
				" verify sign data of server trusted"
				" with ASUE error.\n");
				return wapi_err_VerifyASUEASUSignFailure;
			}
		}


	if (AccessAuthRespPacket.cervalidresult.cerresult2 != 0)
		{
			if (WAPISendDisconnectEv() != 0)
			{
				wpa_printf(MSG_ERROR,
				"WAPI: WAPISendDisconnectEv failed");
			}

			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_CERT_INVALID;

			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);

			wpa_printf(MSG_ERROR,
			"WAPI: Access Auth Resp - verify AE cert error");

			return wapi_err_VerifyAECertificateAuthResult;

		}

	if (AccessAuthRespPacket.cervalidresult.cerresult1 != 0)
		{
			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_CERT_INVALID;

			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);

			wpa_printf(MSG_ERROR,
			"WAPI: Access Auth Resp - verify ASUE cert error");

			return wapi_err_VerifyAECertificateAuthResult;

		}

	}

	//Calculate BK
	if ( !CalculateBKFromXYPN1N2(bx,
		&AccessAuthRespPacket.aekeydata,
		AccessAuthRespPacket.aechallenge,
		bAsueChallenge,
		bBK,
		bLastAuthID))
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
		"WAPI: Access Auth Resp - Calculate BK failed");

		return wapi_err_OtherFaild;

	}
	else
	{
		g_eWaiStatus = WAIPS_AUTH_OK;

		wpa_printf(MSG_ERROR,
			"WAPI: Access Auth Resp processed successfully");

		return 0;
	}


}


uint32  ProcessWAPIProtocolSessNegRequ(const uint8 * buffer, uint16 bufflen)
{
	wlan_wapi_iface_auth_result_type res;

	uint8	bBit4;
	uint8	bBit00;

	uint8  bCurrentBKID[16] = {0};
	unsigned long * rr;
	uint8  bSessionKey[96] = {0};
	uint8  bLastSessionAERand[RAND_LEN] = {0};
	wapi_param_set  tWIEasue;
	uint8  bHMACData[HMAC_LEN] = {0};
	CONTX  contx;

	uint8  bAddIDBuffer[12] = {0};
	uint8  bInputBuffer[12 + RAND_LEN * 2] = {0};

	uint8 *bTempDataBuffer = NULL;
	uint16 nTempDataBufferLen = 0;

	short usReturnUnPackRes = 0;
	uint8 m = 0;

	wapi_handshake_err = 0;
	wpa_printf(MSG_ERROR, " %s: WAPI: Staues=%d ",__func__,g_eWaiStatus);
	memset(&SessionKeyNegRequPacket, 0, sizeof(SessionKeyNegRequPacket));

	usReturnUnPackRes = unpack_session_key_neg_requ(
				&SessionKeyNegRequPacket, buffer, bufflen);


	if (usReturnUnPackRes == PACK_ERROR)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
		"%s WAPI: Unicast Key Req UnPack format error",__func__);

		return wapi_err_UnPackSessNegRequ;
	}

	wpa_printf(MSG_DEBUG,"%s WAPI: Unicast Key Req UnPack success",
					__func__);

	if(g_connect_data.config_params.auth_type ==
		WLAN_WAPI_IFACE_AUTH_TYPE_CERT)
	{
		memcpy(bAddIDBuffer, g_bAPBSSIDMac, 6);
		memcpy(bAddIDBuffer + 6, g_bSTAMac, 6);

		KD_hmac_sha256(bAddIDBuffer,
			12,
			bBK,
			16,
			bCurrentBKID,
			BKID_LEN);

		if (memcmp(bCurrentBKID, &SessionKeyNegRequPacket.bkid,
			BKID_LEN) != 0)
		{
			wpa_printf(MSG_ERROR,"%s WAPI: bCurrentBKID and "
			"SessionKeyNegRequPacket.bkid are not same",__func__);

			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);

			return wapi_err_BKSAInvalidate;

		}

	}
	else if (g_connect_data.config_params.auth_type ==
		WLAN_WAPI_IFACE_AUTH_TYPE_PSK)
	{
		if (!GetBKFromPreShareKey(
		g_connect_data.config_params.auth_info.psk_info.psk_val_type.passphrase,
		g_connect_data.config_params.auth_info.psk_info.psk_type, bBK))
		{
			wpa_printf(MSG_ERROR,"%s WAPI: Unicast Key Req -"
					" Derive BK from PSK ",__func__);
		}


		memcpy(bAddIDBuffer, g_bAPBSSIDMac, 6);
		memcpy(bAddIDBuffer + 6, g_bSTAMac, 6);

		KD_hmac_sha256(bAddIDBuffer,
			12,
			bBK,
			16,
			bCurrentBKID,
			BKID_LEN);

		if (memcmp(bCurrentBKID, &SessionKeyNegRequPacket.bkid,
				BKID_LEN) != 0)
		{
			wpa_printf(MSG_ERROR,"%s WAPI: Unicast Key Req - "
				"PSK is NOT same (BKID mismatch)",__func__);

			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PSK_INVALID;

			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);
			wapi_handshake_err = wapi_err_BKIDMisMatch;
			return wapi_err_BKIDMisMatch;
		}
	}

	bBit4 = (SessionKeyNegRequPacket.flag & 16) >> 4;

	if (bBit4 != 0)
	{
		bBit00 = SessionKeyNegRequPacket.uskid & 1;

		if (bFirstSessionKey)
		{
			bUSKIDSARec = bBit00;

			if (bBit00 != bUSKIDSA)
			{
				res.result =
				WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
				res.failure_reason =
				WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

				wlan_wapi_iface_auth_result_ind(
					g_wapi_iface_handle, res);

				wpa_printf(MSG_ERROR,"%s WAPI: Unicast Key Req-"
				" USKSA for USKID is invalid", __func__);

				return wapi_err_USKSAInvalidate;

			 }
		}
		else
		{
			bUSKIDSARec = !bUSKIDSARec;

			if (bBit00 != bUSKIDSARec)
			{
				res.result =
				WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
				res.failure_reason =
				WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

				wlan_wapi_iface_auth_result_ind(
					g_wapi_iface_handle, res);
				wpa_printf(MSG_ERROR,"%s WAPI: Unicast Key Req-"
				" USKSA for USKID is invalid",__func__);
				return wapi_err_USKSAInvalidate;
			}
		}

		if (memcmp(bLastAEChallenge,
			SessionKeyNegRequPacket.aechallenge, RAND_LEN) != 0)
		{
			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
									res);

			wpa_printf(MSG_ERROR,"%s WAPI: Unicast Key Req - "
				"AE Challenge mismatch",__func__);


			return wapi_err_AEChallengeMisMatch;
		}

	}

	memset(bAsueChallenge, 0, RAND_LEN);
	rr = (unsigned long *)bAsueChallenge;
	generate_random( rr );
	rr = (unsigned long *)bAsueChallenge + 4;
	generate_random(rr);

	memcpy(bAddIDBuffer, g_bAPBSSIDMac, 6);
	memcpy(bAddIDBuffer + 6, g_bSTAMac, 6);

	memcpy(bInputBuffer, bAddIDBuffer, 12);
	memcpy(bInputBuffer + 12, &SessionKeyNegRequPacket.aechallenge,
	RAND_LEN);
	memcpy(bInputBuffer + 12 + RAND_LEN, bAsueChallenge, RAND_LEN);

	prf_pairkey96(bBK, bInputBuffer, 12 + RAND_LEN * 2, bSessionKey);

	memcpy(bUEK, bSessionKey + 0, 16);
	memcpy(bUCK, bSessionKey + 16, 16);
	memcpy(bMAK, bSessionKey + 32, 16);
	memcpy(bKEK, bSessionKey + 48, 16);
	memcpy(bLastSessionAERand, bSessionKey + 64, RAND_LEN);

	contx.buff = bLastSessionAERand;
	contx.length = RAND_LEN;

	if (mhash_sha256(&contx,
		1,
		bLastAEChallenge,
		RAND_LEN) == 0)
	{
		wpa_printf(MSG_ERROR,"WAPI: Unicast Key Req - Current AE"
			" challenge doesn't match with last AE challenge");

		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);
		return wapi_err_AUTH_PROTOCOL_FAIL;

	}

	memset(&tWIEasue, 0, sizeof(wapi_param_set));

	tWIEasue.elementID = WAPI_ELE_ID;
	tWIEasue.version = WAPI_PROTO_VERSION;
	tWIEasue.akmnumber = WAPI_AKM_LENGTH;

	if( g_connect_data.config_params.auth_type ==
		WLAN_WAPI_IFACE_AUTH_TYPE_PSK)
	{
	    tWIEasue.akmlist[0] = WAPI_AKM_PSK;
	}
	else if( g_connect_data.config_params.auth_type ==
		WLAN_WAPI_IFACE_AUTH_TYPE_CERT )
	{
		tWIEasue.akmlist[0] = WAPI_AKM_CERT;
	}

	tWIEasue.singlecodenumber = WAPI_SINGLECODE_LENGTH;
	tWIEasue.singlecodelist[0] = WPI_SMS4;
	tWIEasue.multicode = WPI_SMS4;
	tWIEasue.wapiability = 0x0000;
	tWIEasue.bkidnumber = 0x0000;
	tWIEasue.length = 0x16;

	SessionKeyNegRespPacket.flag = SessionKeyNegRequPacket.flag;
	memcpy(SessionKeyNegRespPacket.bkidentify, bCurrentBKID, BKID_LEN);
	SessionKeyNegRespPacket.uskid = SessionKeyNegRequPacket.uskid;
	memcpy(&SessionKeyNegRespPacket.addid,
		&SessionKeyNegRequPacket.addid, 12);
	memcpy(SessionKeyNegRespPacket.asuechallenge, bAsueChallenge, RAND_LEN);
	memcpy(SessionKeyNegRespPacket.aechallenge,
		SessionKeyNegRequPacket.aechallenge, RAND_LEN);
	memcpy(&SessionKeyNegRespPacket.wieasue, &tWIEasue, sizeof(tWIEasue));

	bPackBKID = TRUE;

	bTempDataBuffer = senddatabuffer;
	memset(bTempDataBuffer, 0, BUFF_SPLIT_SIZE);

	nTempDataBufferLen = 0;
	nTempDataBufferLen = pack_session_key_neg_resp_to_buffer(
		&SessionKeyNegRespPacket, bTempDataBuffer, BUFF_SPLIT_SIZE);

	if ( nTempDataBufferLen == PACK_ERROR)
	{
		wpa_printf(MSG_ERROR,"%s WAPI: Unicast Key Req -"
			" Unicast Key Resp pack failed",__func__);
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);
		return wapi_err_AUTH_PROTOCOL_FAIL;
	}

	if (!CalculateHMACData(bTempDataBuffer, nTempDataBufferLen, bMAK, bHMACData))
	{
		wpa_printf(MSG_ERROR,"%s WAPI: Unicast Key Req -"
			" CalculateHMACData failed", __func__);
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		return wapi_err_AUTH_PROTOCOL_FAIL;
	}


	memcpy(SessionKeyNegRespPacket.hmac, bHMACData, HMAC_LEN);

	bPackBKID = TRUE;

	memset(bTempDataBuffer, 0, BUFF_SPLIT_SIZE);

	nTempDataBufferLen = pack_session_key_neg_resp(&SessionKeyNegRespPacket,
				 bTempDataBuffer, BUFF_SPLIT_SIZE);

	if(nTempDataBufferLen == PACK_ERROR)
	{
		wpa_printf(MSG_ERROR,"%s WAPI: Unicast Key Req -"
		" Unicast Key Resp pack to sendbuffer failed", __func__);
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);
		return wapi_err_AUTH_PROTOCOL_FAIL;
	}
	else
	{
		nSendPacketLen = nTempDataBufferLen;

		if(!WAPIProtocolSend88B4Packet(senddatabuffer, nSendPacketLen))
		{
			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);

			wpa_printf(MSG_ERROR, "%s WAPI: Unicast Key Resp packet"
				" send failed", __func__);
			return wapi_err_SendSessionNegResp;
		}

		g_eWaiStatus = WAIPS_KEY_NEGING;
		if(nTmSessionNegResp)
		{
			wlan_wapi_iface_stop_timer(nTmSessionNegResp);
			wlan_wapi_iface_delete_timer(nTmSessionNegResp);
			nTmSessionNegResp = 0;
			nNumResendSessNegResp = 0;
			nCountResendSessNegResp = 0;
		}
		if(nTmSessionNegResp == 0)
		{
			nNumResendSessNegResp = 0;
			nCountResendSessNegResp = 0;
			nTmSessionNegResp = wlan_wapi_iface_create_timer(
			TimerProcResendSessNegResp,1);
			wlan_wapi_iface_start_timer(nTmSessionNegResp,
				SESSIONNEGRESP_TIMEOUT);
		}
		wpa_printf(MSG_ERROR,"WAPI: Unicast Key Resp sent,"
			"Waiting for Unicast Key Confimation.....");
	}

	return 0;

}



uint32  ProcessWAPIProtocolSessNegAck(const uint8 * buffer, uint16 bufflen)
{
	wlan_wapi_iface_auth_result_type res;
	wlan_wapi_iface_cmd_type	cmd;

	uint8  bBit4;
	short usReturnUnPackRes = 0;
	uint8 *bTempDataBuffer;
	uint8  bWIEaeAck[MAX_WAPI_IE_LEN];
	int   nAckLen;
	int   nGlobalLen;
	uint32 sms;
	uint8 bBit00;


       if( (g_eWaiStatus == WAIPS_KEY_NEG_OK) ||
           (g_eWaiStatus == WAIPS_GRP_NOTIFYING) ||
           (g_eWaiStatus == WAIPS_GRP_NOTIFY_OK))
	{
		wpa_printf(MSG_ERROR,
		"%s WAPI: Unicast Key update already completed. Current State:%d",
		__func__,g_eWaiStatus);
		return 0;
	}

	if (g_eWaiStatus != WAIPS_KEY_NEGING)
	{
		wpa_printf(MSG_ERROR,
		"%s WAPI: Unicast Key Confim recvd in %d state", __func__,
		g_eWaiStatus);
		return wapi_err_ProcessStatues_KEY_NEGING;
	}

	memset(&SessionKeyNegAckPacket, 0, sizeof(SessionKeyNegAckPacket));
	memset(bWIEaeAck, 0, MAX_WAPI_IE_LEN);

	bUnPackBKID = FALSE;

	usReturnUnPackRes = unpack_session_key_neg_ack(&SessionKeyNegAckPacket,
				buffer, bufflen);

	if (usReturnUnPackRes == PACK_ERROR)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
		"%s WAPI: Unicast Key Confim unpack failed",__func__);
		return wapi_err_UnPackSessNegAck;
	}

	wpa_printf(MSG_ERROR, "%s WAPI: Unicast Key Confim Received", __func__);

	wlan_wapi_iface_stop_timer(nTmSessionNegResp);


	if ( memcmp(&SessionKeyNegAckPacket.asuechallenge, &SessionKeyNegRespPacket.asuechallenge, RAND_LEN) != 0)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
		"%s WAPI: Unicast Key Confim ASUE challenge mismatch",
		__func__);
		return wapi_err_ASUEChallengeMisMatch;
	}

	bTempDataBuffer = senddatabuffer;

	memset(bTempDataBuffer, 0, BUFF_SPLIT_SIZE);

	memcpy(bTempDataBuffer, buffer + WAPI_HEADER_LEN,
	bufflen - WAPI_HEADER_LEN - HMAC_LEN);

	if (!VerifyPacketHMACData(
		bTempDataBuffer,
		bufflen - WAPI_HEADER_LEN - HMAC_LEN,
		bMAK,
		SessionKeyNegAckPacket.hmac))
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
		"%s WAPI: Unicast Key Confim - verify HMAC failed", __func__);
		return wapi_err_VerifyHMACFailure;
	}

	bBit4 = (SessionKeyNegAckPacket.flag & 16) >> 4;

	while (bBit4 == 0)
	{
		nAckLen = SessionKeyNegAckPacket.wie[1] + 2;
		nGlobalLen = g_ieAssocAp[1] + 2;

		bPackBKID = FALSE;

		memcpy(bWIEaeAck, SessionKeyNegAckPacket.wie, MAX_WAPI_IE_LEN);

		if (nAckLen!=nGlobalLen || memcmp(bWIEaeAck, g_ieAssocAp,
		nAckLen))
		{
			//WIEae is not same
			if (WAPISendDisconnectEv() != 0)
			{
				wpa_printf(MSG_ERROR,
				"%s WAPI: WAPISendDisconnectEv failed",
				__func__);
			}

			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);

			wpa_printf(MSG_ERROR,
			"%s WAPI: WAPI IE in unicast key confirm not matched"
			"with IE in Beacon frame", __func__);
			return wapi_err_WIEaeMisMatch;
		}
		break;
	}

	wlan_wapi_iface_status_ind(g_wapi_iface_handle,
	WLAN_WAPI_IFACE_WAI_STATUS_EV_USK_DERIVED);
	sms = WPI_SMS4;
	cmd.cmd_id = WLAN_WAPI_IFACE_CMD_SET_KEYS;
	cmd.cmd_info.set_keys_cmd.keyListNum = 0;
	memcpy(cmd.cmd_info.set_keys_cmd.Keys[0].cipherSuite,&sms,4);
	cmd.cmd_info.set_keys_cmd.Keys[0].initiator = 1;
	memcpy(cmd.cmd_info.set_keys_cmd.Keys[0].key,bUEK,16);
	memcpy(&(cmd.cmd_info.set_keys_cmd.Keys[0].key[16]),bUCK,16);
	cmd.cmd_info.set_keys_cmd.Keys[0].keyIndex =
			SessionKeyNegAckPacket.uskid;
	cmd.cmd_info.set_keys_cmd.Keys[0].keyLen = 32;
	cmd.cmd_info.set_keys_cmd.Keys[0].keyType = WLAN_WAPI_IFACE_KEY_TYPE_U;
	cmd.cmd_info.set_keys_cmd.Keys[0].mSeqNum = 0;

	memcpy(cmd.cmd_info.set_keys_cmd.Keys[0].peerMacAddress,
	g_bAPBSSIDMac, WLAN_WAPI_IFACE_MAC_ADDR_LEN);

	if(wlan_wapi_iface_ioctl(g_wapi_iface_handle,&cmd) ==
		WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE)
	{
		wpa_printf(MSG_ERROR,
		"%s WAPI: Unicast Key installation failed",__func__);
		return wapi_Unicast_Key_installation_Failed;
	}
	else
	{
		wpa_printf(MSG_INFO,
		"%s WAPI: Unicast Key installation successful", __func__);
	}

	g_eWaiStatus = WAIPS_KEY_NEG_OK;

	bBit00 = SessionKeyNegRequPacket.uskid & 1;

	if ((bBit4 == 1) && (bBit00 == bUSKIDSARec))
	{
		wpa_printf(MSG_INFO,
		"%s WAPI: Unicast Re-Key update successful",__func__);

		bFirstSessionKey = FALSE;
		g_eWaiStatus = WAIPS_GRP_NOTIFY_OK;
		return 0;
	}

	return 0;

}

uint32  ProcessWAPIProtocolGroupKeyNotice(const uint8 * buffer, uint16 bufflen)
{
	wlan_wapi_iface_auth_result_type res;
	uint8   bKeyOut[32] = {0};
	uint8   bHMACData[HMAC_LEN] = {0};
	short usReturnUnPackRes = 0;
	uint8 *bTempDataBuffer = NULL;
	uint16 nTempDataBufferLen = 0;
	uint8 pTempNotifyKeyIdentify[IV_LEN] = {0};

	uint32 sms;
	wlan_wapi_iface_cmd_type cmd;

	if (g_eWaiStatus != WAIPS_KEY_NEG_OK && g_eWaiStatus != WAPIS_WAI_BEGIN
		&& g_eWaiStatus != WAIPS_GRP_NOTIFY_OK)
	{
		wpa_printf(MSG_ERROR,
		"%s WAPI: Group Key Ann recvd in invalid state %d\n",
		__func__, g_eWaiStatus);
		return wapi_err_ProcessStatues_KEY_NEGING_and_wai_not_begin;
	}

	memset(&GroupKeyNotifyPacket, 0, sizeof(GroupKeyNotifyPacket));

	wpa_printf(MSG_ERROR, "WAPI: Group Key Ann recvd");

	usReturnUnPackRes = unpack_groupkey_notify_requ(
			&GroupKeyNotifyPacket, buffer, bufflen);
	if (usReturnUnPackRes == PACK_ERROR)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
		"WAPI: Group Key Ann packet unpack failed");

		return wapi_err_UnPackGroupKeyNotice;

	}

	bTempDataBuffer = senddatabuffer;
	nTempDataBufferLen = 0;

	memset(bTempDataBuffer, 0, BUFF_SPLIT_SIZE);
	memcpy(bTempDataBuffer, buffer + WAPI_HEADER_LEN,
	bufflen - WAPI_HEADER_LEN - HMAC_LEN);

	if (!VerifyPacketHMACData(
		bTempDataBuffer,
		bufflen - WAPI_HEADER_LEN - HMAC_LEN,
		bMAK,
		GroupKeyNotifyPacket.hmac))
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
		"WAPI: Group Key Ann - verify HMAC failed");

		return wapi_err_VerifyHMACFailure;

	}

	memcpy(pTempNotifyKeyIdentify, GroupKeyNotifyPacket.notifykeyidentify,
		IV_LEN);

	if (wpi_decrypt(
		pTempNotifyKeyIdentify,
		GroupKeyNotifyPacket.notifykeydata.data,
		GroupKeyNotifyPacket.notifykeydata.length,
		bKEK,
		bNMK
		) == 1)
	{
		res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
		res.failure_reason =
		WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

		wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle, res);

		wpa_printf(MSG_ERROR,
		"WAPI: Group Key Ann unpack main key failed");
		return wapi_err_DecryptNMKFailure;
	}

	memcpy(GroupKeyNotifyPacket.notifykeyidentify,
	pTempNotifyKeyIdentify, IV_LEN);

	prf_multikey32(bNMK, bKeyOut);

	wlan_wapi_iface_status_ind(g_wapi_iface_handle,
	WLAN_WAPI_IFACE_WAI_STATUS_EV_MSK_DERIVED);
	memcpy(bNEK, bKeyOut + 0, 16);
	memcpy(bNCK, bKeyOut + 16, 16);

	GroupKeyRespPacket.flag = GroupKeyNotifyPacket.flag;
	GroupKeyRespPacket.notifykeyindex = GroupKeyNotifyPacket.notifykeyindex;
	GroupKeyRespPacket.singlekeyindex = GroupKeyNotifyPacket.singlekeyindex;
	memcpy(&GroupKeyRespPacket.addid, &GroupKeyNotifyPacket.addid, MAC_LEN * 2);
	memcpy(GroupKeyRespPacket.notifykeyidentify,
	GroupKeyNotifyPacket.notifykeyidentify, IV_LEN);

	memset(bTempDataBuffer, 0, BUFF_SPLIT_SIZE);

	nTempDataBufferLen = pack_groupkey_notify_resp_to_buffer(
				&GroupKeyRespPacket, bTempDataBuffer,
				BUFF_SPLIT_SIZE);

	if (nTempDataBufferLen == PACK_ERROR)
	{
		wpa_printf(MSG_ERROR,"WAPI: Pack Group Key Resp failed");
		return wapi_Pack_Group_Key_Resp_Failed;
	}

	if (!CalculateHMACData(bTempDataBuffer, nTempDataBufferLen,
		bMAK, bHMACData))
	{
		wpa_printf(MSG_ERROR,"WAPI: Group Key Ann - HMAC mismatch");
		return wapi_Pack_Group_Key_Hmac_mismatch;
	}

	memcpy(GroupKeyRespPacket.hmac, bHMACData, HMAC_LEN);

	memset(bTempDataBuffer, 0, BUFF_SPLIT_SIZE);

	nTempDataBufferLen = pack_groupkey_notify_resp(&GroupKeyRespPacket,
				bTempDataBuffer, BUFF_SPLIT_SIZE);

	if(nTempDataBufferLen == PACK_ERROR)
	{
		wpa_printf(MSG_ERROR,
		"WAPI: Pack Group Key Resp packet failed");
	}
	else
	{
		nSendPacketLen = nTempDataBufferLen;

		if (WAPIProtocolSend88B4Packet(senddatabuffer, nSendPacketLen))
		{
			wpa_printf(MSG_INFO,
			"WAPI: Group Key Notify Resp packet successfully sent");

			sms = WPI_SMS4;
			cmd.cmd_id = WLAN_WAPI_IFACE_CMD_SET_KEYS;
			cmd.cmd_info.set_keys_cmd.keyListNum = 1;
			memcpy(cmd.cmd_info.set_keys_cmd.Keys[1].cipherSuite,
				&sms, 4);
			cmd.cmd_info.set_keys_cmd.Keys[1].initiator = 1;
			memcpy(cmd.cmd_info.set_keys_cmd.Keys[1].key, bNEK, 16);
			memcpy(&(cmd.cmd_info.set_keys_cmd.Keys[1].key[16]),
				bNCK, 16);
			cmd.cmd_info.set_keys_cmd.Keys[1].keyIndex =
			GroupKeyRespPacket.notifykeyindex;
			cmd.cmd_info.set_keys_cmd.Keys[1].keyLen = 32;
			cmd.cmd_info.set_keys_cmd.Keys[1].keyType =
			WLAN_WAPI_IFACE_KEY_TYPE_M;
			cmd.cmd_info.set_keys_cmd.Keys[1].mSeqNum = 0;

			memset(cmd.cmd_info.set_keys_cmd.Keys[1].peerMacAddress,
				0xFF, WLAN_WAPI_IFACE_MAC_ADDR_LEN);

			if(wlan_wapi_iface_ioctl(g_wapi_iface_handle,&cmd)
				== WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE)
			{
				wpa_printf(MSG_ERROR,
				"WAPI: Multicast keys installation failed");
				return wapi_Unicast_Key_installation_Failed;
			}
			else
			{
				wpa_printf(MSG_INFO,
				"WAPI: Multicast keys installation successful");
			}
			g_eWaiStatus = WAIPS_GRP_NOTIFY_OK;
			wpa_printf(MSG_INFO,
			"WAPI: WAPI Protocol Handshake complete");

			bFirstSessionKey = FALSE;

			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_SUCCESS;
			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);

			return 0;
		}
		else
		{
			res.result = WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE;
			res.failure_reason =
			WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL;

			wlan_wapi_iface_auth_result_ind(g_wapi_iface_handle,
							res);
			wpa_printf(MSG_ERROR,
			"WAPI: Failed to send Group Key Notify Resp packet");

			return wapi_err_SendGroupKeyResp;

		}
	}
	return 0;
}
