/*=============================================================================
WLAN_WAPI_X509.C

DESCRIPTION

EXTERNALIZED FUNCTIONS


=======================================================================*/

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

#include<math.h>
#include <stdio.h>
#include <memory.h>

#include "wlan_wapi_iface_os_svc.h"
#include "wlan_wapi_x509.h"

boolean x509_get(const uint8* pCert, X509 *x509);
X509 s_x509;

static void InitX509(X509 * x509)
{
	static boolean s_bx509init = FALSE;
	static uint8 s_buf_x509[512] = {0};
	uint8* p = s_buf_x509;


	if (s_bx509init)
		return;
	s_bx509init = TRUE;
	memset(&s_x509, 0, sizeof(s_x509));


	x509->cert_info = ( st_x509_tmp1 )p;
	p += sizeof(*x509->cert_info);
	x509->cert_info->serialNumber = (ASN1_INTEGER*)p;
	p += sizeof(ASN1_INTEGER);
	x509->cert_info->key = ( st_x509_tmp2 )p;
	p += sizeof(*x509->cert_info->key);
	x509->cert_info->key->public_key = (ASN1_BIT_STRING*)p;
	p += sizeof(ASN1_BIT_STRING);
	x509->cert_info->validity = (st_x509_tmp3)p;
	p += sizeof(*x509->cert_info->validity);
	x509->cert_info->validity->notBefore = (ASN1_TIME*)p;
	p += sizeof(ASN1_TIME);
	x509->cert_info->validity->notAfter = (ASN1_TIME*)p;
	p += sizeof(ASN1_TIME);
	x509->cert_info->issuer = (X509_NAME1*)p;
	p += sizeof(X509_NAME1);
	x509->cert_info->subject = (X509_NAME1*)p;
	p += sizeof(X509_NAME1);

	x509->cert_info->serialNumber->data = p;
	x509->cert_info->key->public_key->data = p + 32;
	x509->cert_info->validity->notBefore->data = p + 96;
	x509->cert_info->validity->notAfter->data = p + 128;
	x509->cert_info->issuer->data = p + 160;
	x509->cert_info->subject->data = p + 288;
}

X509* d2i_wapi_X509(X509 **a, const unsigned char **in, long len)
{
	InitX509(&s_x509);
	if (x509_get(*in, &s_x509))
	{
		*a = &s_x509;
		return &s_x509;
	}
	return NULL;
}

X509_NAME1* X509_get_subject_name_wapi(X509 *a)
{
	return a->cert_info->subject;
}

X509_NAME1* X509_get_issuer_name(X509 *a)
{
	return a->cert_info->issuer;
}

ASN1_INTEGER* X509_get_serialNumber(X509 *a)
{
	return a->cert_info->serialNumber;
}

int i2d_X509_NAME(X509_NAME1 *a, unsigned char **out)
{
	memcpy(*out, a->data, a->length+2);
	return a->length+2;
}

int i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **out)
{
	unsigned char *p = *out;
	p[0] = 2;
	p[1] = a->length;
	memcpy(p+2, a->data, a->length);
	return a->length+2;
}


typedef struct _x509inf
{
	/*type*/
	int t;
	/*len*/
	int l;
	/*len of head*/
	int lh;
	/*to dat*/
	uint8* pd;
	/*to next*/
	uint8* pn;
	/*to childs*/
	uint8* psub[9];
	/*count of sub*/
	int csub;
} x509inf;

static int x509_getlen(const uint8* p, int* pl, int* plh)
{
	int l = p[1];
	int lh = 2;
	if (l > 127)
	{
		lh += l & 7;
		if (0x81 == p[1])
			l = p[2];
		else if (0x82 == p[1])
			l = (p[2]<<8) + p[3];
		else
			l = p[2];
	}
	if (NULL != pl)
		*pl = l;
	if (NULL != plh)
		*plh = lh;
	return l + lh;
}

static x509inf x509_get_inf(const uint8* p)
{
	x509inf i;
	int j;
	const uint8* q;

	memset(&i, 0, sizeof(i));
	i.t = p[0];
	i.pn = (uint8*)(p + x509_getlen(p, &i.l, &i.lh));
	i.pd = (uint8*)(p + i.lh);
	if (0x30 == i.t || 0x31 == i.t || (i.t >= 0xA0 && i.t <= 0xA9))
	{

		q = i.pd;
		for (j = 0; j < 9&&q < i.pn; j++)
		{
			i.psub[j] = (uint8*)q;
			q = q + x509_getlen(q, NULL, NULL);
		}
		i.csub = j;
	}
	return i;
}

static void x509_cpdat(const uint8* p, void* pd, boolean inchead)
{
	ASN1_INTEGER* q = (ASN1_INTEGER*)pd;
	x509inf i = x509_get_inf(p);
	q->length = i.l;
	if (inchead)
		memcpy(q->data, p, i.l+i.lh);
	else
		memcpy(q->data, i.pd, i.l);
}

void x509_getprtstr(const X509_NAME1* pn, byte_data* pd)
{
	x509inf i = x509_get_inf(pn->data);
	int k;
	for (k = 0; k < i.csub; k++)
	{
		x509inf ix = x509_get_inf(i.psub[k]);
		x509inf ix0 = x509_get_inf(ix.psub[0]);

		unsigned char id_cn[12] = {6, 3, 0x55, 4, 3};
		if (ix0.psub[0][1] == id_cn[1] && 0 ==
				memcmp(ix0.psub[0], id_cn, 2+id_cn[1]))
		{
			x509inf ix01 = x509_get_inf(ix0.psub[1]);
			pd->length = ix01.l;
			memcpy(pd->data, ix01.pd, ix01.l);
			return;
		}
	}
	/*set error */
	pd->length = 5;
	memcpy(pd->data, "error", 5);
}

void x509_getprtstr_ca(const X509_NAME1* pn, byte_data* pd)
{
	x509inf i = x509_get_inf(pn->data);
	int k;
	for (k = 0; k < i.csub; k++)
	{
		x509inf ix = x509_get_inf(i.psub[k]);
		x509inf ix0 = x509_get_inf(ix.psub[0]);

		unsigned char id_ou[12] = {6, 3, 0x55, 4, 0xB};
		if (ix0.psub[0][1] == id_ou[1] && 0 ==
			memcmp(ix0.psub[0], id_ou, 2+id_ou[1]))
		{
			x509inf ix01 = x509_get_inf(ix0.psub[1]);
			pd->length = ix01.l;
			memcpy(pd->data, ix01.pd, ix01.l);
			return;
		}
	}

	pd->length = 5;
	memcpy(pd->data, "error", 5);
}


static boolean x509_check_name(const uint8* pn)
{
	x509inf i = x509_get_inf(pn);
	if (0x30 != i.t || i.csub < 2 || i.l > 127)
		return FALSE;

	int k, j;
	boolean b[5] = {0};

	printf("check name new \r\n");
	for (k = 0; k < i.csub; k++)
	{
		x509inf ix = x509_get_inf(i.psub[k]);
		if (0x31 != ix.t || ix.csub < 1)
		{
			return FALSE;
		}

		x509inf ix0 = x509_get_inf(ix.psub[0]);
		if (0x30 != ix0.t || ix0.csub < 2)
		{
			return FALSE;
		}
		unsigned char id[5][12] = {
				{6, 0xA, 9, 0x92, 0x26, 0x89, 0x93, 0xF2,
				0x2C, 0x64, 1, 0x19},
				{6, 3, 0x55, 4, 6},
				{6, 3, 0x55, 4, 0xA},
				{6, 3, 0x55, 4, 0xB},
				{6, 3, 0x55, 4, 3},
			};
		for (j = 0; j < 5; j++)
		{
			if (ix0.psub[0][1] == id[j][1] && 0 ==
				memcmp(ix0.psub[0], id[j], 2+id[j][1]))
			{
				b[j] = TRUE;
				break;
			}
		}
	}
	return b[4];
}

boolean x509_get(const uint8* pCert, X509 *x509)
{
	x509inf i;
	uint8* psub[9] = {0};
	uint8* pt0;
	uint8* pt1;
	uint8* pk;


	i = x509_get_inf(pCert);
	if (0x30 != i.t || i.csub < 1 || i.l > 8192)
		return FALSE;
	i = x509_get_inf(i.pd);
	if (0x30 != i.t || i.csub < 7 || i.l > 8192)
		return FALSE;
	if (0 != memcmp(i.pd, "\xa0\3\2\1\2", 5))
		return FALSE;


	memcpy(psub, i.psub, 9*sizeof(uint8*));

	if (2 != psub[1][0] || 0 == psub[1][1] || psub[1][1] > 32)
		return FALSE;
	if (!x509_check_name(psub[3]))
		return FALSE;
	if (!x509_check_name(psub[5]))
		return FALSE;

	i = x509_get_inf(psub[4]);
	if (0x30 != i.t || i.csub < 2)
		return FALSE;
	pt0 = i.psub[0];
	if (0x17 != pt0[0] || pt0[1] > 32)
		return FALSE;
	pt1 = i.psub[1];
	if (0x17 != pt1[0] || pt1[1] > 32)
		return FALSE;

	i = x509_get_inf(psub[6]);
	if (0x30 != i.t || i.csub < 2)
		return FALSE;
	pk = i.psub[1];
	if (3 != pk[0] || pk[1] > 64)
		return FALSE;

	x509_cpdat(psub[1], x509->cert_info->serialNumber, FALSE);
	x509_cpdat(psub[3], x509->cert_info->issuer, TRUE);
	x509_cpdat(pt0, x509->cert_info->validity->notBefore, FALSE);
	x509_cpdat(pt1, x509->cert_info->validity->notAfter, FALSE);
	x509_cpdat(psub[5], x509->cert_info->subject, TRUE);

	i = x509_get_inf(pk);
	x509->cert_info->key->public_key->length = i.l-1;
	memcpy(x509->cert_info->key->public_key->data, i.pd+1, i.l-1);

	return TRUE;
}
