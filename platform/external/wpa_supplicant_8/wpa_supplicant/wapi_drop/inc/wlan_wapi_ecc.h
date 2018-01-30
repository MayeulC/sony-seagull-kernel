/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef __WLAN_WAPI_ECC_H_
#define __WLAN_WAPI_ECC_H_

/*=============================================================================
WLAN_WAPI_ECC.H

DESCRIPTION

EXTERNALIZED FUNCTIONS


===========================================================*/

/*========================================================

		EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     ----------------------------------------

============================================================*/

/*==========================================================

    INCLUDE FILES FOR MODULE

===========================================================*/
#include "wlan_wapi_iface_os_svc.h"


#ifdef _cplusplus
 extern "C" {
#endif

#define MINTLENGTH    13
#define PARABUFFER    6
#define PARABYTELEN   24
#define POINTTABLELEN 128


#define MI_BITS_PER_BYTE    8
#define MI_BYTES_PER_WORD	(sizeof (uint32))

#define MI_NEGATIVE     2
#define OUTPUT_LEN   6
#define OUTPUT_SIZE  5

#define MI_BYTES_PER_WORD	(sizeof (uint32))
#define MI_WORD_SIZE	(sizeof (uint32) * MI_BITS_PER_BYTE)


#ifndef max
	#define max(a, b) a>b?a:b
#endif

#ifndef min
	#define min(a, b) a<b?a:b
#endif


typedef struct {
	int length ;
	uint32 value[MINTLENGTH];
	int Field_type;
} MInt;
typedef struct {
	MInt x;
	MInt y;
	MInt z;
} EcFpPointProject;

typedef struct {
	int  isInfinite;
	MInt x;
	MInt y;
} EcFpPoint;

typedef struct {
	unsigned int *x;      /* x coordinate of this point */
	unsigned int *y;      /* y coordinate of this point */
} Point;

typedef struct contxt
{
	unsigned char* buff;
	unsigned length;
} CONTX;


typedef	struct {
	MInt P;
	MInt A;
	MInt B;
	MInt seed;
	EcFpPoint BasePoint;
	MInt Order;
	MInt cofactor;
} EllipticCurve;


#define prf_hmac_sha256 KD_hmac_sha256
#define FP_IsZero(ptr) (((((ptr)->length == 1) && \
		((ptr)->value[0] == 0))) || ((ptr)->length==0))
#define MI_WordToMInt(srcWord,destInt) {if(srcWord==0)	(destInt)->length=0; \
		else	(destInt)->length =1;	(destInt)->value[0] = srcWord;}
#define FPSqr_Mul(a, p, product) FP_Mul(a, a, p, product)
#define FP_Move(source, destination) MI_Move(source, destination)
#define FP_Equal(operand1, operand2) (!MI_Compare (operand1, operand2))


void KD_hmac_sha256(unsigned char* t, unsigned tl, unsigned char* k,
		unsigned kl, unsigned char* o, unsigned ol);
int wapi_hmac_sha256(unsigned char* t, int tl, unsigned char* k,
		unsigned kl, unsigned char* o, unsigned ol);
static int ECFpDoubleProj (EcFpPointProject *operand,MInt *a,
		MInt *b, MInt *prime, EcFpPointProject *result);
static int ECFpAddProj (EcFpPointProject *addend1, EcFpPoint *addend2,
		MInt *a, MInt * b,MInt *prime, EcFpPointProject *result);
long asue_random(long s);
int MI_RecomputeLength (int targetLength,MInt *theInt);
int DW_AddProduct (uint32 *a, uint32 *b, uint32 c, uint32 *d,
		 unsigned int length);
int MI_ModularReduce (MInt *operand,MInt *modulus,MInt *reducedValue);
int OctetStringToPriKey(const unsigned char *OString, unsigned int OSLen,
		unsigned int *piPrivateKey,int *piLenOfPriKey);
int OctetStringToPubKey(const unsigned char *OString, unsigned int OSLen,
		Point *poPublicKey);
int Sign_With_Private_Key(uint8 *pbSignOut, const uint8 *pbData,
		int iLenIn, const unsigned int *piPrivateKey,int iLenOfPriKey);
int ECC_Init(void);
void prf_preshared(const unsigned char* key, unsigned keylen,
		unsigned char* keyout);
int Verify_With_Public_Key(const uint8 *pbData, int iDataLen,
		const uint8 *pbSignIn, int iSignInLen, const Point oPubPoint);
int KTimesPoint(unsigned int *piPrivateKey, int *piLenOfPriKey,
		Point *poTempPublicKey, const int iKeyBitLen1,
		Point *poAddPoint, const int iKeyBitLen2);
int PriKeyToOctetString(unsigned int *piPrivateKey, int piLenOfPriKey,
		unsigned int OSBuffSize, unsigned int *OSLen,
		unsigned char *DString);
int Generate_PubKey(unsigned int *piPrivateKey,
		int piLenOfPriKey, Point *poPublicKey);
int PubKeyToOctetString(Point *poPublicKey, unsigned int OSBuffSize,
		unsigned int *OSLen, unsigned char *DString);
void prf_pairkey96(const unsigned char* key, unsigned char* buffer,
		unsigned bufferlen, unsigned char* keyout);
void prf_multikey32(const unsigned char* key, unsigned char* keyout);


int mhash_sha256_contx(const CONTX *contx, unsigned length,
		 unsigned char* digest, unsigned digest_length);
#define mhash_sha256 mhash_sha256_contx


typedef Point *PointTable;


#ifdef _cplusplus
 }
#endif


#endif	/*__WLAN_WAPI_ECC_H_*/
