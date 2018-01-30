/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef __WLAN_WAPI_STRUCTURE_H_
#define __WLAN_WAPI_STRUCTURE_H_

/*=============================================================================
WLAN_WAPI_STRUCTURE.H

DESCRIPTION

EXTERNALIZED FUNCTIONS


===========================================================================*/

/*===========================================================================

			EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ----------------------------------------------------------

===========================================================================*/


#define INCLUDE_WAPI_MEM

#ifdef INCLUDE_WAPI_MEM
#define MAX_DATA_LEN                65535
#define WAPI_SIZEOF_IDENTITY        772
#define MAX_X509_DATA_LEN           4096 * 2
#define MAX_CERTIFICAT_DATA_LEN     4096 * 2
#define WAPI_SIZEOF_CERTIFICATE     MAX_X509_DATA_LEN+4
#else
#define MAX_DATA_LEN                2048
#define WAPI_SIZEOF_IDENTITY        772
#define MAX_X509_DATA_LEN           1024
#define MAX_CERTIFICAT_DATA_LEN     1024
#define WAPI_SIZEOF_CERTIFICATE     MAX_X509_DATA_LEN+4
#endif

#define MAX_BYTE_DATA_LEN       256
#define SIGN_LEN                48
#define PUBKEY_LEN              48
#define SECKEY_LEN              24
#define DIGEST_LEN              32
#define TAG_LEN                 16
#define HMAC_LEN                20
#define IV_LEN                  16
#define MIC_LEN                 16

#define PN_LEN                  16

#define REPUT_LEN               16

#define RAND_LEN                32

#define MAC_LEN                 6
#define BKID_LEN                16

#define MAX_EXTENSION_ATTR_NUMBER   8
#define MAX_IDENTITY_NUMBER         16
#define MAX_TURTLENECK_NUMBER       16

#ifndef WLAN_WAPI_IFACE_WAPI_IE_MAX_LEN
#define MAX_WAPI_IE_LEN             256
#else
#define MAX_WAPI_IE_LEN	WLAN_WAPI_IFACE_WAPI_IE_MAX_LEN
#endif


#define MAX_COMM_DATA_LEN           65535

#define MAX_PDU_DATA_LEN            4096

#define  PACK_ERROR   (uint16)-1

#ifdef BIG_ENDIAN
#define htonl(x) x
#define htons(x) x
#define ntohl(x) x
#define ntohs(x) x
#else
#define htonl(x) \
	((uint32)((((uint32)(x) & 0x000000ffU) << 24) | \
	(((uint32)(x) & 0x0000ff00U) <<  8) | \
	(((uint32)(x) & 0x00ff0000U) >>  8) | \
	(((uint32)(x) & 0xff000000U) >> 24)))
#define htons(x) \
	((uint16)((((uint16)(x) & 0x00ff) << 8) | \
	(((uint16)(x) & 0xff00) >> 8)))

#define ntohl(x) \
	((uint32)((((uint32)(x) & 0x000000ffU) << 24) | \
	(((uint32)(x) & 0x0000ff00U) <<  8) | \
	(((uint32)(x) & 0x00ff0000U) >>  8) | \
	(((uint32)(x) & 0xff000000U) >> 24)))
#define ntohs(x) \
	((uint16)((((uint16)(x) & 0x00ff) << 8) | \
		(((uint16)(x) & 0xff00) >> 8)))
#endif

#define WAPI_ECDSA_OID          "1.2.156.11235.1.1.1"

#define WAPI_ECC_CURVE_OID      "1.2.156.11235.1.1.2.1"

#define ECDSA_ECDH_OID          "1.2.840.10045.2.1"

typedef struct _WAPIOID
{
	const char*   pszOIDName;
	uint16        wOIDLen;
	uint16        wParamLen;
	uint8         bOID[MAX_BYTE_DATA_LEN];
	uint8         bParameter[MAX_BYTE_DATA_LEN];
} WAPIOID, *PWAPIOID;

#define WAPI_OID_NUMBER     1
extern const WAPIOID gSignArithmeticOID[WAPI_OID_NUMBER];
extern const WAPIOID gPubKeyOID[WAPI_OID_NUMBER];

#define WAPI_ELE_ID             ((uint8)68)


#ifdef BIG_ENDIAN
#define WAPI_OUI                ((uint32)0x00147200)
#define WAPI_AKM_PSK            ((WAPI_AKML_PSK )  | WAPI_OUI)
#define WAPI_AKM_CERT           ((WAPI_AKML_CERT ) | WAPI_OUI)
#define WPI_SMS4                (WAPI_CIPHER_SMS4 | WAPI_OUI)
#else
#define WAPI_OUI                ((uint32)0x00721400)
#define WAPI_AKM_PSK            ((WAPI_AKML_PSK << 24)  | WAPI_OUI)
#define WAPI_AKM_CERT           ((WAPI_AKML_CERT << 24) | WAPI_OUI)
#define WPI_SMS4                ((WAPI_CIPHER_SMS4 << 24) | WAPI_OUI)

#endif

typedef enum _WAPI_AKM
{
	WAPI_AKML_RESV = 0,
	WAPI_AKML_CERT,
	WAPI_AKML_PSK
}WAPI_AKM;



typedef enum _WAPI_CIPHER
{
	WAPI_CIPHER_RESV = 0,
	WAPI_CIPHER_SMS4
} WAPI_CIPHER;

typedef struct _byte_data
{
	uint8  length;
	uint8  data[MAX_BYTE_DATA_LEN];
}byte_data;

typedef struct _byte_data2
{
	int    length;
	uint8  data[MAX_BYTE_DATA_LEN];
}byte_data2;

typedef struct _Mybyte_data
{
	int     length;
	uint8   data[4096];
}Mybyte_data;

typedef struct _comm_data
{
	uint16  length;
	uint8   data[MAX_COMM_DATA_LEN];
}comm_data;

typedef struct _username_data
{
	uint8   length;
	uint8   data[MAX_BYTE_DATA_LEN];
}username_data;

typedef struct _sign_data
{
	uint16  length;
	uint8   data[MAX_BYTE_DATA_LEN];
}sign_data;

typedef struct _pdu_data
{
	uint16  length;
	uint8   data[MAX_PDU_DATA_LEN];
}pdu_data;

typedef struct _der_identity
{
	uint8  data[MAX_BYTE_DATA_LEN * 3];
}der_identity;

typedef struct _packet_head
{
	uint16   version;
	uint8    type;
	uint8    subtype;
	uint16   reserved;
	uint16   length;
	uint16   packetnumber;
	uint8    fragmentnumber;
	uint8    identify;
}packet_head;

typedef struct _oid_param
{
	uint8  oid_code[MAX_BYTE_DATA_LEN];
}oid_param;


typedef struct _sign_arithmetic
{
	uint16      length;
	uint8       hash_identify;
	uint8       sign_identify;
	uint8       param_identify;
	uint16      param_length;
	oid_param   oid;
}sign_arithmetic;


typedef struct _subject_pubkey
{
	uint16      length;
	uint8       pubkey_arithmetic_identify;
	uint8       param_identify;
	uint16      param_length;
	oid_param   oid;
	uint8       pubkey_value[MAX_BYTE_DATA_LEN];
}subject_pubkey;

typedef struct _ecdh_param
{
	uint8       param_identify;
	uint16      param_length;
	oid_param   oid;
}ecdh_param;

typedef struct _extension_attribute
{
	uint8            type;
	uint16           length;
	username_data    issure_cer_username;
	uint32           issure_cer_serialnumber;
}extension_attribute;

typedef struct _identity
{
	uint16           identity_identify;
	uint16           identity_length;
	der_identity     cer_der;
}identity;

typedef struct _addindex
{
	uint8       mac1[MAC_LEN];
	uint8       mac2[MAC_LEN];
}addindex;

typedef struct _pov
{
	uint32   starttime;
	uint32   endtime;
}pov;

typedef struct _KERNEL_CERTIFICATE
{

	uint16            cer_identify;
	uint16            cer_length;
	uint8             cer_buffer[MAX_CERTIFICAT_DATA_LEN];
}KERNEL_CERTIFICATE;

typedef struct _certificate
{
	uint16            cer_identify;
	uint16            cer_length;
	uint8             cer_X509[MAX_X509_DATA_LEN];
}certificate;

typedef  struct  _private_key
{
	uint8             tVersion;
	uint8             lVersion;
	uint8             vVersion;

	uint8             tPrivateKey;
	uint8             lPrivateKey;
	uint8             vPrivateKey[MAX_BYTE_DATA_LEN];

	uint8             tSPrivateKeyAlgorithm;
	uint8             lSPrivateKeyAlgorithm;
	uint8             tOID;
	uint8             lOID;
	uint8             vOID[MAX_BYTE_DATA_LEN];

	uint8             tSPubkey;
	uint8             lSPubkey;
	uint8             tPubkey;
	uint8             lPubkey;
	uint8             vPubkey[MAX_BYTE_DATA_LEN];

}private_key;

typedef struct _sign_attribute
{
	uint8             type;
	uint16            length;
	identity          signidentity;
	sign_arithmetic   signarithmetic;
	sign_data         sign;
}sign_attribute;

typedef struct _certificate_valid_result
{
	uint8             type;
	uint16            length;
	uint8             random1[RAND_LEN];
	uint8             random2[RAND_LEN];
	uint8             cerresult1;
	certificate       certificate1;
	uint8             cerresult2;
	certificate       certificate2;
}certificate_valid_result;

typedef struct _identity_list
{
	uint8         type;
	uint16        length;
	uint8         reserved;
	uint16        identitynumber;
	identity      identityset[MAX_IDENTITY_NUMBER];
}identity_list;


typedef struct _auth_active
{
	uint8           flag;
	uint8           authidentify[RAND_LEN];
	identity        localasuidentity;
	certificate     certificatestaae;
	ecdh_param      ecdhparam;
}auth_active;


typedef struct _certificate_auth_requ
{
	addindex           addid;
	uint8              aechallenge[RAND_LEN];
	uint8              asuechallenge[RAND_LEN];
	certificate        staasuecer;
	certificate        staaecer;
	identity_list      asuidentitylist;
}certificate_auth_requ;

typedef struct _access_auth_requ
{
	uint8             flag;
	uint8             authidentify[RAND_LEN];
	uint8             asuechallenge[RAND_LEN];
	byte_data         asuekeydata;
	identity          staasueidentity;
	certificate       certificatestaasue;
	ecdh_param        ecdhparam;
	identity_list     asuidentitylist;
	sign_attribute    asuesign;
}access_auth_requ;


typedef struct _certificate_auth_resp
{
	addindex                   addid;
	certificate_valid_result   cervalidresult;
	sign_attribute             asueassign;
	sign_attribute             aeassign;
}certificate_auth_resp;

typedef struct _access_auth_resp
{
	uint8                        flag;
	uint8                        asuechallenge[RAND_LEN];
	uint8                        aechallenge[RAND_LEN];
	uint8                        accessresult;
	byte_data                    asuekeydata;
	byte_data                    aekeydata;
	identity                     staaeidentity;
	identity                     staasueidentity;

	certificate_valid_result     cervalidresult;
	sign_attribute               asueassign;
	sign_attribute               aeassign;

	sign_attribute               aesign;
}access_auth_resp;

typedef  struct  _session_key_neg_requ
{
	uint8                         flag;
	uint8                         bkid[BKID_LEN];
	uint8                         uskid;
	addindex                      addid;
	uint8                         aechallenge[RAND_LEN];
}session_key_neg_requ;

/* BKID */
typedef struct _bkid
{
	uint8                 bkidentify[BKID_LEN];
}bkid;


typedef struct  _wapi_param_set
{
	uint8                 elementID;
	uint8                 length;
	uint16                version;
	uint16                akmnumber;
	uint32                akmlist[MAX_TURTLENECK_NUMBER];
	uint16                singlecodenumber;
	uint32                singlecodelist[MAX_TURTLENECK_NUMBER];
	uint32                multicode;
	uint16                wapiability;
	uint16                bkidnumber;
	bkid                  bkidlist[MAX_TURTLENECK_NUMBER];
}wapi_param_set;


typedef struct _wpa_param_set
{
	enum
	{
		cmax = 8
	};
	uint8 id;			//offset:0
	uint8 len;			//offset:1
	uint8 oui[4];		//offset:2
	short ver;			//offset:6
	int multi;			//offset:8
	short cuni;			//offset:12, this mark m
	int uni[cmax];		//offset:14
	short cakm;			//offset:14 + 4*m
	int akm[cmax];		//offset:16 + 4*m

	int tPrivacy;
	int encrypt;
}wpa_param_set;


typedef struct _session_key_neg_resp
{
	uint8                 flag;
	uint8                 bkidentify[BKID_LEN];
	uint8                 uskid;
	addindex              addid;
	uint8                 asuechallenge[RAND_LEN];
	uint8                 aechallenge[RAND_LEN];
	wapi_param_set        wieasue;
	uint8                 hmac[HMAC_LEN];
}session_key_neg_resp;

typedef struct  _session_key_neg_ack
{
	uint8                flag;
	uint8                bkidentify[BKID_LEN];
	uint8                uskid;
	addindex             addid;
	uint8                asuechallenge[RAND_LEN];
	uint8				 wie[MAX_WAPI_IE_LEN];
	uint8                hmac[HMAC_LEN];
}session_key_neg_ack;


typedef struct  _groupkey_notify_requ
{
	uint8               flag;
	uint8               notifykeyindex;
	uint8               singlekeyindex;
	addindex            addid;
	uint8               pn[PN_LEN];
	uint8               notifykeyidentify[IV_LEN];
	byte_data           notifykeydata;
	uint8               hmac[HMAC_LEN];
} groupkey_notify_requ;

typedef struct  _groupkey_notify_resp
{
	uint8             flag;
	uint8             notifykeyindex;
	uint8             singlekeyindex;
	addindex          addid;
	uint8             notifykeyidentify[IV_LEN];
	uint8             hmac[HMAC_LEN];
} groupkey_notify_resp;

typedef struct  _stakey_create_requ
{
	uint8            flag;
	uint8            stakeyindex;
	uint8            singlekeyindex;
	addindex         addid;
	uint8            reputcount[REPUT_LEN];
	uint8            hmac[HMAC_LEN];
} stakey_create_requ;


typedef struct  _pre_auth_start
{
	uint8            flag;
	uint8            singlekeyindex;
	addindex         addid;
	uint8            reputcount[REPUT_LEN];
	uint8            hmac[HMAC_LEN];
} pre_auth_start;


typedef  struct  _attribute
{
	uint16   identify;
	uint16   length;
	uint8    data[MAX_X509_DATA_LEN];
}attribute;


typedef  enum  _WAI_PROCESS_STATUS
{
	WAIPS_NONE =0,
	WAIPS_IDEL,
	WAPIS_WAI_BEGIN,
	WAIPS_AUTHING,
	WAIPS_AUTH_OK,
	WAIPS_KEY_NEGING,
	WAIPS_KEY_NEG_OK,
	WAIPS_GRP_NOTIFYING,
	WAIPS_GRP_NOTIFY_OK,

}WAI_PROCESS_STATUS;

#endif /*__WLAN_WAPI_STRUCTURE_H_*/
