/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright (C) 2012 Sony Mobile Communications AB.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef WLAN_WAPI_IFACE_H
#define WLAN_WAPI_IFACE_H
/*====================================================================

File: WLAN_WAPI_IFACE.H

DESCRIPTION
    This header file exposes WAPI APIs to 3rd party WAPI supplicant that wishes
    to interface with AMSS WLAN framework.


* Copyright (c) 2012 Qualcomm Atheros, Inc.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/
/*===========================================================================*/
/*========================================================================

			EDIT HISTORY FOR FILE

$Header: //depot/asic/sandbox/projects/wlan/wapi/wlan_wapi_iface.h#7 $
$Author: rkonda $ $DateTime: 2009/06/24 14:24:23 $

This section contains comments describing changes made to the module.
Notice that changes are listed in reverse chronological order.

when        who     what, where, why
--------    ---     ----------------------------------------------------------
08/18/09    pbh     Added Key Negotiation start enum
06/12/09    rko     Initial Creation
===========================================================================*/
#include "wlan_wapi_iface_os_svc.h"

struct list_head {	struct list_head *next, *prev;};


/*===========================================================================

PUBLIC DATA DECLARATIONS

=====================================================================*/
/* Max size of the WAPI information element as per spec */
#define WLAN_WAPI_IFACE_WAPI_IE_MAX_LEN             255
/* EtherType of WAI pkt */
#define WLAN_WAPI_IFACE_WAI_ETHERTYPE_TYPE          0x88B4
  /* MAX SSID length */  /* MAC address length */
#define WLAN_WAPI_IFACE_SSID_MAX_LEN                32
  /* MAC address length */
#define WLAN_WAPI_IFACE_MAC_ADDR_LEN                6
 /* Max passphrase length for PSK */
#define WLAN_WAPI_IFACE_PSK_PASSPHRASE_MAX_LEN      32
 /* Certificate file path max length */
#define WLAN_WAPI_IFACE_CERT_FILE_PATH_MAX_LEN      255
  /* 16 Encryption Key+ 16 Integrity Check Key */
#define WLAN_WAPI_IFACE_KEY_MAX_LEN                 32
 /* Unicast Key Type */
#define WLAN_WAPI_IFACE_KEY_TYPE_U                  0
 /* Multicast Key Type */
#define WLAN_WAPI_IFACE_KEY_TYPE_M                  1
/* STA Key Type */
#define WLAN_WAPI_IFACE_KEY_TYPE_S                  2
 /* Max number of keys */
#define WLAN_WAPI_IFACE_MAX_KEYS_NUM                4
 /* Max length of extended command supported */
#define WLAN_WAPI_IFACE_EXTENDED_CMD_MAX_LEN        512
/* Max length of extended event supported */
#define WLAN_WAPI_IFACE_EXTENDED_EV_MAX_LEN         512

#define WLAN_WAPI_IFACE_BKID_LEN                    16
/* BK Length */
#define WLAN_WAPI_IFACE_BK_LEN                      32
  /* Maximum number of BKSA cache supported */
#define WLAN_WAPI_IFACE_BKSA_CACHE_MAX              10

/**
* TYPEDEF WLAN_WAPI_IFACE_WAI_STATUS_ENUM_TYPE
*
* DESCRIPTION
* Various events ASUE can notify WAPI IFACE layer regarding WAI
* progress
* */
typedef enum
{
	/* WAI Authentication start event */
	WLAN_WAPI_IFACE_WAI_STATUS_EV_AUTH_START        = 0,
	/* WAI Key Negotiation Start event */
	WLAN_WAPI_IFACE_WAI_STATUS_EV_KEY_NEG_START     = 1,
	/* WAI Unicast key derived event */
	WLAN_WAPI_IFACE_WAI_STATUS_EV_USK_DERIVED       = 2,
	/* WAI Multicast Key derived event */
	WLAN_WAPI_IFACE_WAI_STATUS_EV_MSK_DERIVED       = 3,
	/* WAI Re-Key start event */
	WLAN_WAPI_IFACE_WAI_STATUS_EV_REKEY_START       = 4,
	/* WAI Re-Key finish event */
	WLAN_WAPI_IFACE_WAI_STATUS_EV_REKEY_FINISH      = 5,
	/* WAI Authentication max event */
	WLAN_WAPI_IFACE_WAI_STATUS_EV_MAX

} wlan_wapi_iface_wai_status_event_enum_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_EVENT_ENUM_TYPE
*
* DESCRIPTION
* Various WLAN events that WAPI IFACE layer can notify ASUE
* */
typedef enum
{
	WLAN_WAPI_IFACE_EV_NONE                         = 0,
	/* WLAN adapter connected to AP */
	WLAN_WAPI_IFACE_EV_CONNECT                      = 1,
	/* WLAN adapter disconnected from AP */
	WLAN_WAPI_IFACE_EV_DISCONNECT                   = 2,
	/* WLAN extended event from adapter   */
	WLAN_WAPI_IFACE_EV_EXTENDED                     = 101,

	WLAN_WAPI_IFACE_EV_MAX
} wlan_wapi_iface_event_enum_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_SSID_TYPE
*
* DESCRIPTION
* SSID definition
* */
typedef struct
{
	/* SSID length */
	uint8 len;
	 /* SSID value*/
	uint8 ssid[WLAN_WAPI_IFACE_SSID_MAX_LEN];
} wlan_wapi_iface_ssid_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_PSK_PASSPHRASE_ENUM_TYPE
*
* DESCRIPTION
* PSK Passphrase type (Hex or Ascii)
* */
typedef enum
{
	/* PSK passphrase is in ASCII   */
	WLAN_WAPI_IFACE_PSK_PASSPHRASE_TYPE_ASCII       = 0,
	/* PSK passphrase is in Hex */
	WLAN_WAPI_IFACE_PSK_PASSPHRASE_TYPE_HEX         = 1
} wlan_wapi_iface_psk_passphrase_enum_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_PASSPHRASE_INFO_TYPE
*
* DESCRIPTION
* PSK passphrase information
* */
typedef struct
{
	 /* PSK passphrase is ASCII or Hex */
	wlan_wapi_iface_psk_passphrase_enum_type psk_type;

	struct
	{
	 /* Passphrase length */
	uint32  len;
	/* Passphrase for WAPI PSK*/
	uint8   passphrase[WLAN_WAPI_IFACE_PSK_PASSPHRASE_MAX_LEN];
	} psk_val_type;

} wlan_wapi_iface_passphrase_info_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_CERT_ENUM_TYPE
*
* DESCRIPTION
* Certificate type for WAI Authentication (X.509, GBW)
* */
typedef enum
{
	/* Certificate is X.509 V3 */
	WLAN_WAPI_IFACE_CERT_TYPE_X509                  = 0,
	/* Certificate is GBW  */
	WLAN_WAPI_IFACE_CERT_TYPE_GBW                   = 1
} wlan_wapi_iface_cert_enum_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_CERT_INFO_TYPE
*
* DESCRIPTION
* Certificate information & path in the file system where file is
* located
* */
typedef struct
{
	/* WAPI certificate type */
	wlan_wapi_iface_cert_enum_type  cert_type;
	/* WAPI Keystore path */
	uint8  cert_file_uri[WLAN_WAPI_IFACE_CERT_FILE_PATH_MAX_LEN];
} wlan_wapi_iface_cert_info_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_AUTH_ENUM_TYPE
*
* DESCRIPTION
* WAPI AKM type.
* */
typedef enum
{
	/* Authentication is Open */
	WLAN_WAPI_IFACE_AUTH_TYPE_OPEN                  = 0,
	/* Authentication is WAPI PSK */
	WLAN_WAPI_IFACE_AUTH_TYPE_PSK                   = 1,
	/* Authentication is WAPI Certificate */
	WLAN_WAPI_IFACE_AUTH_TYPE_CERT                  = 2

} wlan_wapi_iface_auth_enum_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_CONFIG_PARAMS_TYPE
*
* DESCRIPTION
* WAPI configuration related parameters
* */
typedef struct
{
	/* WAPI authentication type */
	wlan_wapi_iface_auth_enum_type		auth_type;

	struct
	{
	/* WAPI PSK information */
	wlan_wapi_iface_passphrase_info_type    psk_info;
	/* WAPI certificate information */
	wlan_wapi_iface_cert_info_type          cert_info;
	wlan_wapi_iface_cert_info_type          user_key_cert_info;
	wlan_wapi_iface_cert_info_type          as_cert_info;
	 /* WAPI certificate information */
	wlan_wapi_iface_cert_info_type          user_cert_info;
	} auth_info;

} wlan_wapi_iface_config_params_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_CONNECT_EVENT_TYPE
*
* DESCRIPTION
* Parameters associated with connect event
* */
typedef struct
{
	/* SSID of the AP that STA is connected to */
	wlan_wapi_iface_ssid_type	ssid;
	/* BSSID of the AP that STA is connected to */
	uint8	bssid[WLAN_WAPI_IFACE_MAC_ADDR_LEN];
	 /* Station MAC address */
	uint8	sta_mac_address[WLAN_WAPI_IFACE_MAC_ADDR_LEN];
	/* Various WAPI authentication related configuration parameters */
	wlan_wapi_iface_config_params_type  config_params;

	struct
	{
	/* Length of WAPI IE received in beacon or probe response frames */
	uint32	ie_len;
	 /* WAPI IE received in beacon or probe response frames  */
	uint8	ie_data[WLAN_WAPI_IFACE_WAPI_IE_MAX_LEN];
	} beacon_probe_wapi_ie;

	struct
	{
	/* Length of WAPI IE sent in association req by WLAN adapter */
	uint32	ie_len;
	/* WAPI IE sent in association req by WLAN adapter */
	uint8	ie_data[WLAN_WAPI_IFACE_WAPI_IE_MAX_LEN];
	/* WAPI parameter set sent in the association request frame */
	} assoc_req_wapi_ie;

	struct
	{
	/* Is BKSA valid? */
	boolean     bksa_valid;
	/* Base Key ID */
	uint8       bkid[WLAN_WAPI_IFACE_BKID_LEN];
	/* Base Key */
	uint8       bk[WLAN_WAPI_IFACE_BK_LEN];
	} cached_bksa;

} wlan_wapi_iface_connect_event_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_DISCONNECT_REASON_ENUM_TYPE
*
* DESCRIPTION
* Disconnect event reason codes.
* */
typedef enum
{
	/* WLAN adapter disconnect reason none */
	WLAN_WAI_IFACE_DISCONNECT_REASON_NONE               = 0,
	/* WLAN STA lost AP link */
	WLAN_WAI_IFACE_DISCONNECT_REASON_SYSTEM_LOST        = 1,
	/* WLAN STA deauthenticated by AP   */
	WLAN_WAPI_IFACE_DISCONNECT_REASON_AUTH_FAIL         = 2,
	 /* User triggered WLAN disconnection   */
	WLAN_WAPI_IFACE_DISCONNECT_REASON_USER_INITIATED    = 3,

	WLAN_WAPI_IFACE_DISCONNECT_REASON_MAX
} wlan_wapi_iface_disconnect_reason_enum_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_DISCONNECT_EVENT_TYPE
*
* DESCRIPTION
* Parameters associated with disconnect event type
* */
typedef struct
{
	/* Reason why STA is disconnected form AP */
	wlan_wapi_iface_disconnect_reason_enum_type reason;

} wlan_wapi_iface_disconnect_event_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_EXTENDED_INFO_EVENT_TYPE
*
* DESCRIPTION
* Extended event which will be tunneled by WAPI IFACE layer from
* wlan adapter to ASUE
* */
typedef struct
{
	/* Length of the extended event buffer */
	uint32    len;
	/* Extended event buffer */
	uint8     ev_buff[1];

} wlan_wapi_iface_extended_info_event_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_EVENT_INFO_TYPE
*
* DESCRIPTION
* Union of events that WAPI IFACE layer could pass to ASUE
* */
typedef union
{
	/* Connect event from WAPI IFACE to ASUE*/
	wlan_wapi_iface_connect_event_type          connect_ev;
	/* Disconnect event from WAPI IFACE to ASUE*/
	wlan_wapi_iface_disconnect_event_type       disconnect_ev;
	/* Extended event from WLAN adapter to ASUE tunneled by WAPI IFACE*/
	wlan_wapi_iface_extended_info_event_type    ext_info_ev;

} wlan_wapi_iface_event_info_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_EVENT_TYPE
*
* DESCRIPTION
* Event definition for events that WAPI IFACE layer could pass
* to ASUE
* */
typedef struct
{
	/* Event ID of the event from WAPI IFACE to ASUE */
	wlan_wapi_iface_event_enum_type             event_id;
	/* Event information associated with particular event ID */
	wlan_wapi_iface_event_info_type             event_info;
} wlan_wapi_iface_event_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_CMD_ENUM_TYPE
*
* DESCRIPTION
* Enumeration of various commands that ASUE could pass to WLAN
* IFACE layer
* */
typedef enum
{
	/* IOCTL command none */
	WLAN_WAPI_IFACE_CMD_NONE                    = 0,
	/* IOCTL command set WAPI keys */
	WLAN_WAPI_IFACE_CMD_SET_KEYS                = 1,
	/* IOCTL command delete WAPI keys */
	WLAN_WAPI_IFACE_CMD_DEL_KEYS                = 2,
	/* IOCTL command disconnect from AP */
	WLAN_WAPI_IFACE_CMD_DISCONNECT              = 3,
	/* IOCTL command Add/Delete/Update BK Cache */
	WLAN_WAPI_IFACE_CMD_BK_CACHE_OPERATION      = 4,
	/* IOCTL command extended */
	WLAN_WAPI_IFACE_CMD_EXTENDED                = 101,

	WLAN_WAPI_IFACE_CMD_MAX
} wlan_wapi_iface_cmd_enum_type;


/**
*
* TYPEDEF WLAN_WAPI_IFACE_SET_KEY_DESCRIPTOR_TYPE
*
* DESCRIPTION
* Parameters associated with set key descriptor as per the Spec
* */
typedef struct
{

	/* The length of the key in octet */
	uint32    keyLen;
	/* Data encryption key and data integrity key */
	uint8     key[WLAN_WAPI_IFACE_KEY_MAX_LEN];
	/* The number of the key, with a value of 0 or 1 */
	uint32    keyIndex;
	/* Multicast, Unicast,STAKey */
	uint32    keyType;
	/* Peer STA MAC address */
	uint8     peerMacAddress[WLAN_WAPI_IFACE_MAC_ADDR_LEN];
	/* 1 indicates AE or Initiator, 0 indicates ASUE or Peer. */
	uint32    initiator;
	/* The sequence number of the currently encrypted multicast package */
	uint32    mSeqNum;
	/* The cipher suite required for this association */
	uint8     cipherSuite[4];

} wlan_wapi_iface_set_key_descriptor_type;


/**
*
* TYPEDEF WLAN_WAPI_IFACE_SET_KEYS_CMD_TYPE
*
* DESCRIPTION
* Parameters associated with set key cmd as per spec
* */
typedef struct
{
	/* Number of keys to be set */
	uint32	keyListNum;
	/* List of Keys */
	wlan_wapi_iface_set_key_descriptor_type	 Keys[WLAN_WAPI_IFACE_MAX_KEYS_NUM];

} wlan_wapi_iface_set_keys_cmd_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_DEL_KEY_DESCRIPTOR_TYPE
*
* DESCRIPTION
* Parameters associated with delete key descriptor as per the
* Spec
* */
typedef struct
{
	/* Peer STA MAC address */
	uint8     peerMacAddress[WLAN_WAPI_IFACE_MAC_ADDR_LEN];
	/* The number of the key, with a value of 0 or 1 */
	uint32    keyIndex;
	/* Multicast, Unicast,STAKey */
	uint32    keyType;

} wlan_wapi_iface_del_key_descriptor_type;

/**
* TYPEDEF WLAN_WAPI_IFACE_DEL_KEYS_CMD_TYPE
*
* DESCRIPTION
* Parameters associated with del key cmd as per spec
* */
typedef struct
{
	/* Number of keys to be deleted */
	uint32                                      keyListNum;
	/* List of keys */
	wlan_wapi_iface_del_key_descriptor_type     Keys[WLAN_WAPI_IFACE_MAX_KEYS_NUM];

} wlan_wapi_iface_del_keys_cmd_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_EXTENDED_INFO_CMD_TYPE
*
* DESCRIPTION Extended command which will be tunneled by WLAN
* IFACE layer to wlan adapter from ASUE
* */
typedef struct
{
	/* Length of the extended command buffer */
	uint32    len;
	/* Extended command */
	uint8     cmd_buff[1];

}  wlan_wapi_iface_extended_info_cmd_type;

/**
* TYPEDEF WLAN_WAPI_IFACE_AUTH_RESULT_ENUM_TYPE
*
* DESCRIPTION
* Enumeration of BK caching operations that ASUE can perform
* on the cache maintained by WAPI IFACE.
* WAPI IFACE
* */
typedef enum
{
	/* BK Cache operation None */
	WLAN_WAPI_IFACE_BK_CACHE_OP_NONE            = 0,
	/* BK Cache operation Add BKSA */
	WLAN_WAPI_IFACE_BK_CACHE_OP_ADD             = 1,
	/* BK Cache operation Del BKSA */
	WLAN_WAPI_IFACE_BK_CACHE_OP_DEL             = 2,
	/* BK Cache operation Update BKSA */
	WLAN_WAPI_IFACE_BK_CACHE_OP_UPDATE          = 3,

	WLAN_WAPI_IFACE_BK_CACHE_OP_MAX

} wlan_wapi_iface_bk_cache_op_enum_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_BKSA_INFO_TYPE
*
* DESCRIPTION
* Parameters associated with Base Key Security Association info
* */
typedef struct
{
	 /* BSSID of the AP */
	uint8       bssid[WLAN_WAPI_IFACE_MAC_ADDR_LEN];
	/* Base Key ID */
	uint8       bkid[WLAN_WAPI_IFACE_BKID_LEN];
	/* Base Key */
	uint8       bk[WLAN_WAPI_IFACE_BK_LEN];

} wlan_wapi_iface_bksa_info_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_UPDATE_BK_CACHE
*
* DESCRIPTION Add/Delete/Update BK cache in WAPI IFACE
* */
typedef struct
{
	/* Add/Delete/Update BKSA */
	wlan_wapi_iface_bk_cache_op_enum_type       bk_cache_op;
	/* BKSA information */
	wlan_wapi_iface_bksa_info_type              bksa_info_cmd;

}  wlan_wapi_iface_update_bk_cache_cmd_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_CMD_INFO_TYPE
*
* DESCRIPTION
* Union of commands that ASUE can pass to WAPI IFACE layer
* */
typedef union
{
	/* Set keys command form ASUE to WAPI IFACE */
	wlan_wapi_iface_set_keys_cmd_type           set_keys_cmd;
	/* Delete keys command from ASUE to WAPI IFACE  */
	wlan_wapi_iface_del_keys_cmd_type           del_keys_cmd;
	/* Extended command from ASUE to WAPI IFACE*/
	/* to be tunneled to WLAN adpater */
	wlan_wapi_iface_extended_info_cmd_type      ext_info_cmd;
	/* Operate on BK cache maintained by WAPI IFACE */
	wlan_wapi_iface_update_bk_cache_cmd_type    update_bk_cache_cmd;

} wlan_wapi_iface_cmd_info_type;


/**
*
*TYPEDEF WLAN_WAPI_IFACE_CMD_TYPE
*
* DESCRIPTION
* Data type for commands that ASUE could send to WAPI IFACE as
* part of IOCTL.
* */
typedef struct
{
	/* Command ID of the command from ASUE to WAPI IFACE */
	wlan_wapi_iface_cmd_enum_type               cmd_id;
	/* Command information associated with particular command ID */
	wlan_wapi_iface_cmd_info_type               cmd_info;
} wlan_wapi_iface_cmd_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_AUTH_RESULT_ENUM_TYPE
*
* DESCRIPTION
* Enumeration of authentication result that ASUE would notify to
* WAPI IFACE
* */
typedef enum
{
	/* WAPI ASUE authentication result none */
	WLAN_WAPI_IFACE_AUTH_RESULT_NONE            = 0,
	/* WAPI ASUE authentication result success */
	WLAN_WAPI_IFACE_AUTH_RESULT_SUCCESS         = 1,
	/* WAPI ASUE authentication result failure */
	WLAN_WAPI_IFACE_AUTH_RESULT_FAILURE         = 2

} wlan_wapi_iface_auth_result_enum_type;


/**
* TYPEDEF WLAN_WAPI_IFACE_AUTH_FAILURE_REASON_ENUM_TYPE
*
* DESCRIPTION
* Enumeration of various authentication faulure reasons that
* ASUE would notify to WAPI IFACE
* */
typedef enum
{
	/* WAPI ASUE authentication failure unknown */
	WLAN_WAPI_IFACE_AUTH_FAIL_REASON_UNKNOWN            = 0,
	/* WAPI ASUE authentication failure certificate invalid */
	WLAN_WAPI_IFACE_AUTH_FAIL_REASON_CERT_INVALID       = 1,
	/* WAPI ASUE authentication failure PSK invalid */
	WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PSK_INVALID        = 3,
	/* WAPI ASUE authentication failure message timeout */
	WLAN_WAPI_IFACE_AUTH_FAIL_REASON_MSG_TIMEOUT        = 4,
	/* WAPI ASUE authentication failure generic protocol failure*/
	/* for any IE validation failures */
	WLAN_WAPI_IFACE_AUTH_FAIL_REASON_PROTOCOL_FAIL      = 5,

	WLAN_WAPI_IFACE_AUTH_FAIL_REASON_MAX

} wlan_wapi_iface_auth_failure_reason_enum_type;



/**
* TYPEDEF WLAN_WAPI_IFACE_AUTH_RES_TYPE
*
* DESCRIPTION
* AUthentication result data type.
* */
typedef struct
{
	/* WAI Authentication result from ASUE to WAPI IFACE */
	wlan_wapi_iface_auth_result_enum_type               result;
	/*In case of authentication failure,ASUE failure reason to WAPI IFACE*/
	wlan_wapi_iface_auth_failure_reason_enum_type       failure_reason;

} wlan_wapi_iface_auth_result_type;



/**
 * TYPEDEF WLAN_WAPI_IFACE_RETURN_STATUS_TYPE
 *
 * DESCRIPTION
 * Enumeration of generic return status for WAPI IFACE function
 * calls.
 * */
typedef enum
{
	/* Function call return status is Failure */
	WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE          = -1,
	/* Function call return status is Success */
	WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS          = 0,

	WLAN_WAPI_IFACE_RETURN_STATUS_MAX

} wlan_wapi_iface_return_status_enum_type;


/**
*
* TYPEDEF WLAN_WAPI_IFACE_RX_PKT_CBACK_TYPE
*
* DESCRIPTION
* This is the prototype of the packet call back function that
* ASUE registers with WAPI IFACE to get the WAI packets.
* */
typedef void (* wlan_wapi_iface_receive_pkt_cback_type)
(
	uint32           len,
	uint8            *pkt,
	void             *user_data_ptr
 );


/**
* TYPEDEF WLAN_WAPI_IFACE_EVENT_CBACK_TYPE
*
* DESCRIPTION
* This is the prototype of the event call back function that
* ASUE registers with WAPI IFACE to get the WLAN events.
* */
typedef void (* wlan_wapi_iface_event_cback_type)
(
	wlan_wapi_iface_event_type      *wlan_ev,
	void                            *user_data_ptr
 );


/**
* TYPEDEF WLAN_WAPI_IFACE_START_IND_CBACK_TYPE
*
* DESCRIPTION
* This is the prototype of the start indication call back
* function that ASUE registers with WAPI IFACE to be called when
* WAPI IFACE is ready to handle ASUE requests to register
* various call backs. During task initialization, WAPI IFACE
* calls WAPI ASUE specfic initialization XX_Init() function
* provided by WAPI ASUE implemention which takes care of all
* ASUE initalization jobs and returns a function pointer of this
* type to be called whenever WAPI IFACE is ready for ASUE. WAPI
* IFACE also specfies the max MTU size that ASUE needs to
* consider to enable any fragmentataion when sending WAI packets
* to WAPI IFACE.
* */
typedef void (*wlan_wapi_iface_start_ind_cback_type)
(
	uint32 max_mtu_size
 );


/*===========================================================================
  PUBLIC FUNCTIONS
  ===========================================================================*/


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_GET_HANDLE()

DESCRIPTION
  This function is called by the WAPI ASUE as part of start
  indication callback registered with WAPI IFACE. This function
  should be called before any other WAPI IFACE functions. This
  function returns an opaque WAPI IFACE handle to the caller
  which should be used in all subsequent WAPI IFACE functions.
  This is a synchronous call.

PARAMETERS
  void

RETURN VALUE
  void* WAPI IFACE handle

DEPENDENCIES
  None

SIDE EFFECTS
  None
===========================================================================*/
void* wlan_wapi_iface_get_handle
(
	void
 );


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_RELEASE_HANDLE()

DESCRIPTION
  This function is called by the WAPI ASUE to release a handle from WAPI IFACE.
  This function is called by the WAPI ASUE during de-init & also
  in cases where ASUE doesn't need to use the services of WLAN
  IFACE layer anymore & no need to interface with WAPI IFACE.
  ASUE implementataion will provide a XX_Deinit() function that
  WAPI IFACE would call into. This is a synchronous call.

PARAMETERS
  void* WAPI IFACE handle

RETURN VALUE
  WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS -  success
  WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE -  failure

DEPENDENCIES
  None

SIDE EFFECTS
  None
===========================================================================*/
wlan_wapi_iface_return_status_enum_type
wlan_wapi_iface_release_handle
(
	void       *wapi_iface_handle
 );


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_REGISTER_RECEIVE_PKT_CB()

DESCRIPTION
  This function is called by the WAPI ASUE to register a
  callback with WAPI IFACE for incoming WAPI packets. This function
  is called by the WAPI ASUE as part of start indication
  callback registered with WAPI IFACE. As part of registration
  ASUE passes the desired etherType that it is interested in & a
  callback function to be invoked when a pkt of that etherType
  arrives. This is a synchronous call. Callback routine will be
  called by the WAPI IFACE layer when the desired packet type
  arrives. The packet passed to the callback is the buffer that
  contains the 802.2 LLC payload (WAI frame) & the length of the
  buffer. The ownership of this buffer lies with the caller &
  will be freed once the callback function returns.

PARAMETERS
  void*             WAPI IFACE handle
  etherType         WLAN_WAPI_IFACE_WAI_ETHERTYPE_TYPE.
  rx_pkt_f_ptr      call back function to be invoked by WAPI IFACE for incoming
			etherType pkts.
  user_data_ptr     Opaque user data ptr that caller needs to pass back in
			registered call back function.

RETURN VALUE
  WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS -  success
  WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE -  failure

DEPENDENCIES
  None

SIDE EFFECTS
  None
===========================================================================*/
wlan_wapi_iface_return_status_enum_type
wlan_wapi_iface_register_receive_pkt_cb
(
	void                                        *wapi_iface_handle,
	uint16                                      etherType,
	wlan_wapi_iface_receive_pkt_cback_type      rx_pkt_f_ptr,
	void                                        *user_data_ptr
 );


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_REGISTER_WLAN_EVENT_CB()

DESCRIPTION
  This function is called by the WAPI ASUE to register a
  callback with WAPI IFACE for WLAN events. This function is called by the
  WAPI ASUE as part of start indication callback registered with
  WAPI IFACE. As part of this registration ASUE passes a
  callback function to be invoked when certain WLAN events
  happen.

PARAMETERS
  void*             WAPI IFACE handle
  event_f_ptr       call back function to be invoked by
		    WAPI IFACE for WLAN events.
  user_data_ptr     Opaque user data ptr that caller needs to pass back in
			registered call back function.

RETURN VALUE
  WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS -  success
  WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE -  failure

DEPENDENCIES
  None

SIDE EFFECTS
  None
===========================================================================*/
wlan_wapi_iface_return_status_enum_type
wlan_wapi_iface_register_wlan_event_cb
(
	void                                    *wapi_iface_handle,
	wlan_wapi_iface_event_cback_type        event_f_ptr,
	void                                    *user_data_ptr
 );


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_SEND_PKT()

DESCRIPTION
  This function is called by the WAPI ASUE to
  send a WAPI packet to WAPI IFACE. The buffer passed to this
  function is owned by the caller and the caller can free it
  anytime after the call returns.  The passed packet is the
  actual WAI packet that would be encpasulated in the 802.2 LLC
  payload. Caller should ensure that the length of the packet
  cannot be more than the MTU size specfied by the WAPI IFACE as
  part of start indication & ASUE should take care of any WAI
  pkt fragmentation as specified in the spec. This is a
  synchronous call.

PARAMETERS
  void*             WAPI IFACE handle
  etherType         WLAN_WAPI_IFACE_WAI_ETHERTYPE_TYPE
  dst_mac_addr      Destination MAC address to which pkts should be sent.
  param len         Length of the buffer
  param pkt         Pointer to the buffer containing WAI

RETURN VALUE
  WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS -  success
  WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE -  failure

DEPENDENCIES
  None

SIDE EFFECTS
  None
===========================================================================*/
wlan_wapi_iface_return_status_enum_type
wlan_wapi_iface_send_pkt
(
	void               *wapi_iface_handle,
	uint16             etherType,
	uint8              *dst_mac_addr,
	uint32             len,
	uint8              *pkt
 );


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_IOCTL()

DESCRIPTION
  This function is called by the WAPI ASUE to send a command to
  WAPI IFACE layer to be passed down to the WLAN adapter. This
  function takes commands of certain known types & also provides
  a mechanism for ASUE to send a WLAN adapter specfic extended
  command directly to WLAN adapter. The semantics of extended
  commands are not known by WAPI IFACE LAYER & the command is
  just tunneled. This function is a synchronous call.
  If at all there is any need for any ansync confirmation for a
  specfic command from WLAN adapter to ASUE, then extended event
  mechanism could be used where the confirmation would be
  tunneled.

PARAMETERS
  void*             WAPI IFACE handle
  wapi_cmd          Command that ASUE wants to send.

RETURN VALUE
  WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS -  success
  WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE -  failure

DEPENDENCIES
  None

SIDE EFFECTS
  None
===========================================================================*/
wlan_wapi_iface_return_status_enum_type
wlan_wapi_iface_ioctl
(
	void                       *wapi_iface_handle,
	wlan_wapi_iface_cmd_type   *wapi_cmd
 );


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_STATUS_IND()

DESCRIPTION
  This function is called by the WAPI ASUE to update the WAI
  handshake progress to WAPI IFACE layer during WAI AKM. This is
  a non blocking call.

PARAMETERS
  void*             WAPI IFACE handle
  status_ev         Enumeration of various stages of WAI progress

RETURN VALUE
  WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS -  success
  WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE -  failure

DEPENDENCIES
  None

SIDE EFFECTS
  None
===========================================================================*/
wlan_wapi_iface_return_status_enum_type
wlan_wapi_iface_status_ind
(
	void                                              *wapi_iface_handle,
	wlan_wapi_iface_wai_status_event_enum_type        status_ev
 );


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_AUTH_RESULT_IND()

DESCRIPTION
  This function is called by the WAPI ASUE to notify the WAPI
  IFACE about the authentication result which could be SUCCESS
  or FAILURE. In success case, this function should be invoked
  only after successful SET_KEYS_CMD ioctl. This would be the
  trigger for WAPI IFACE to open the controlled port for user
  traffic. This function is a synchronous call.

PARAMETERS
  void*             WAPI IFACE handle
  auth_result       WAI Authentication result

RETURN VALUE
  WLAN_WAPI_IFACE_RETURN_STATUS_SUCCESS -  success
  WLAN_WAPI_IFACE_RETURN_STATUS_FAILURE -  failure

DEPENDENCIES
  None

SIDE EFFECTS
  None
===========================================================================*/
wlan_wapi_iface_return_status_enum_type
wlan_wapi_iface_auth_result_ind
(
	void                               *wapi_iface_handle,
	wlan_wapi_iface_auth_result_type   auth_result
 );

#endif /* WLAN_WAPI_IFACE_H */
