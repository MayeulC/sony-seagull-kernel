/*=============================================================================
WLAN_WAPI_SMS4.C

DESCRIPTION

EXTERNALIZED FUNCTIONS


==========================================================================*/

/*==========================================================================

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

#include "wlan_wapi_sms4const.h"
#define LE
#define ENCRYPT  0
#define DECRYPT  1

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "stdlib.h"

#include "common.h"



void SMS4Crypt(unsigned char *Input, unsigned char *Output, unsigned int *rk)
{
	unsigned int r, mid, x0, x1, x2, x3, *p;
	p = (unsigned int *)Input;
	x0 = p[0];
	x1 = p[1];
	x2 = p[2];
	x3 = p[3];
#ifdef LE
	x0 = Rotl(x0, 16);
	x0 = ((x0 & 0x00FF00FF) << 8) ^ ((x0 & 0xFF00FF00) >> 8);
	x1 = Rotl(x1, 16);
	x1 = ((x1 & 0x00FF00FF) << 8) ^ ((x1 & 0xFF00FF00) >> 8);
	x2 = Rotl(x2, 16);
	x2 = ((x2 & 0x00FF00FF) << 8) ^ ((x2 & 0xFF00FF00) >> 8);
	x3 = Rotl(x3, 16);
	x3 = ((x3 & 0x00FF00FF) << 8) ^ ((x3 & 0xFF00FF00) >> 8);
#endif
	for (r = 0; r < 32; r += 4)
	{
		mid = x1 ^ x2 ^ x3 ^ rk[r + 0];
		mid = ByteSub(mid);
		x0 ^= L1(mid);
		mid = x2 ^ x3 ^ x0 ^ rk[r + 1];
		mid = ByteSub(mid);
		x1 ^= L1(mid);
		mid = x3 ^ x0 ^ x1 ^ rk[r + 2];
		mid = ByteSub(mid);
		x2 ^= L1(mid);
		mid = x0 ^ x1 ^ x2 ^ rk[r + 3];
		mid = ByteSub(mid);
		x3 ^= L1(mid);
	}
#ifdef LE
	x0 = Rotl(x0, 16);
	x0 = ((x0 & 0x00FF00FF) << 8) ^ ((x0 & 0xFF00FF00) >> 8);
	x1 = Rotl(x1, 16);
	x1 = ((x1 & 0x00FF00FF) << 8) ^ ((x1 & 0xFF00FF00) >> 8);
	x2 = Rotl(x2, 16);
	x2 = ((x2 & 0x00FF00FF) << 8) ^ ((x2 & 0xFF00FF00) >> 8);
	x3 = Rotl(x3, 16);
	x3 = ((x3 & 0x00FF00FF) << 8) ^ ((x3 & 0xFF00FF00) >> 8);
#endif
	p = (unsigned int *)Output;
	p[0] = x3;
	p[1] = x2;
	p[2] = x1;
	p[3] = x0;
}

void SMS4KeyExt(unsigned char *Key, unsigned int *rk, unsigned int CryptFlag)
{
	unsigned int r, mid, x0, x1, x2, x3, *p;
	p = (unsigned int *)Key;
	x0 = p[0];
	x1 = p[1];
	x2 = p[2];
	x3 = p[3];
	wpa_printf(MSG_ERROR, "WAPI: SMS4KeyExt \n");
#ifdef LE
	x0 = Rotl(x0, 16);
	x0 = ((x0 & 0xFF00FF) << 8) ^ ((x0 & 0xFF00FF00) >> 8);
	x1 = Rotl(x1, 16);
	x1 = ((x1 & 0xFF00FF) << 8) ^ ((x1 & 0xFF00FF00) >> 8);
	x2 = Rotl(x2, 16);
	x2 = ((x2 & 0xFF00FF) << 8) ^ ((x2 & 0xFF00FF00) >> 8);
	x3 = Rotl(x3, 16);
	x3 = ((x3 & 0xFF00FF) << 8) ^ ((x3 & 0xFF00FF00) >> 8);
#endif
	x0 ^= 0xa3b1bac6;
	x1 ^= 0x56aa3350;
	x2 ^= 0x677d9197;
	x3 ^= 0xb27022dc;
	for (r = 0; r < 32; r += 4)
	{
		mid = x1 ^ x2 ^ x3 ^ CK[r + 0];
		mid = ByteSub(mid);
		rk[r + 0] = x0 ^= L2(mid);
		mid = x2 ^ x3 ^ x0 ^ CK[r + 1];
		mid = ByteSub(mid);
		rk[r + 1] = x1 ^= L2(mid);
		mid = x3 ^ x0 ^ x1 ^ CK[r + 2];
		mid = ByteSub(mid);
		rk[r + 2] = x2 ^= L2(mid);
		mid = x0 ^ x1 ^ x2 ^ CK[r + 3];
		mid = ByteSub(mid);
		rk[r + 3] = x3 ^= L2(mid);
	}
}
