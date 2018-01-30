/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef __WLAN_WAPI_X509_H_
#define __WLAN_WAPI_X509_H_

/*==============================================================
WLAN_WAPI_X509.H

DESCRIPTION

EXTERNALIZED FUNCTIONS


=======================================================================*/

/*=======================================================================

			EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     --------------------------------------------------

=======================================================================*/

#include "wlan_wapi_structure.h"

typedef struct asn1_st
{
	int length;
	unsigned char *data;
}ASN1_INTEGER, ASN1_BIT_STRING, ASN1_TIME, X509_NAME1;


typedef struct _st_x509_tmp2
{
	ASN1_BIT_STRING *public_key;
}*st_x509_tmp2;

typedef struct _st_x509_tmp3
{
	ASN1_TIME *notBefore;
	ASN1_TIME *notAfter;
}*st_x509_tmp3;

typedef struct _st_x509_tmp1
{
	ASN1_INTEGER *serialNumber;
	st_x509_tmp2 key;
	st_x509_tmp3 validity;
	X509_NAME1 *issuer;
	X509_NAME1 *subject;
}*st_x509_tmp1;

typedef struct x509_st
{
	st_x509_tmp1 cert_info;
}X509;


X509* d2i_wapi_X509(X509 **a, const unsigned char **in, long len);
int i2d_X509_NAME(X509_NAME1 *a, unsigned char **out);
X509_NAME1* X509_get_subject_name_wapi(X509 *a);
X509_NAME1* X509_get_issuer_name(X509 *a);
ASN1_INTEGER* X509_get_serialNumber(X509 *a);
int i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **out);


#endif		/*__WLAN_WAPI_X509_H_*/
