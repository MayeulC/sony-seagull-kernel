/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef __WLAN_WAPI_WPI_PCRYPT_H_
#define __WLAN_WAPI_WPI_PCRYPT_H_

/*=====================================================================
WLAN_WAPI_WPI_PCRYPT.H

DESCRIPTION

EXTERNALIZED FUNCTIONS


===================================================================*/

/*==============================================================

			EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ---------------------------------------------

====================================================================*/


#ifdef __cplusplus
 extern "C" {
#endif

int wpi_encrypt(unsigned char * pofbiv_in,
				unsigned char * pbw_in,
				unsigned int plbw_in,
				unsigned char * pkey,
				unsigned char * pcw_out);

int wpi_decrypt(unsigned char * pofbiv_in,
				unsigned char * pcw_in,
				unsigned int plcw_in,
				unsigned char * prkey_in,
				unsigned char * pbw_out);

int wpi_pmac(unsigned char * pmaciv_in,
				unsigned char * pmac_in,
				unsigned int pmacpc_in,
				unsigned char * pkey,
				unsigned char * pmac_out);


#ifdef __cplusplus
}
#endif


#endif		/*__WLAN_WAPI_WPI_PCRYPT_H_*/
