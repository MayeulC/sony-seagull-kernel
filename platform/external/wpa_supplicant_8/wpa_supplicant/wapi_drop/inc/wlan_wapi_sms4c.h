/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef __WLAN_WAPI_SMS4C_H_
#define __WLAN_WAPI_SMS4C_H_

/*=============================================================================
WLAN_WAPI_SMS4C.H

DESCRIPTION

EXTERNALIZED FUNCTIONS


============================================================================*/

/*===========================================================================

			EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ----------------------------------------------------------

===========================================================================*/

void SMS4Crypt(unsigned char *Input, unsigned char *Output, unsigned int *rk);

void SMS4KeyExt(unsigned char *Key, unsigned int *rk, unsigned int CryptFlag);


#endif /*__WLAN_WAPI_SMS4C_H_*/
