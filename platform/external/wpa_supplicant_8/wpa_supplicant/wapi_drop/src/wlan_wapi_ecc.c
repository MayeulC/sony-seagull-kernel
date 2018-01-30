/*=============================================================================
WLAN_WAPI_ECC.C

DESCRIPTION

EXTERNALIZED FUNCTIONS


===========================================================================*/

/*=========================================================================

			 EDIT HISTORY FOR FILE

$Header:  $
$Author:  $ $DateTime:  $

when        who     what, where, why
--------    ---     -------------------------------------------------

* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright (C) 2012 Sony Mobile Communications AB
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.

===========================================================================*/

/*===========================================================================

    INCLUDE FILES FOR MODULE

===========================================================================*/


#include <math.h>
#include "string.h"
#include <time.h>
#include "wlan_wapi_iface_os_svc.h"
#include "wlan_wapi_iface.h"
#include "wlan_wapi_ecc.h"
#include "wlan_wapi_para.h"

#define HALF_WORD_BITS   16
#define BITS_PER_BYTE    8
#define MAX_CMP_HALF_WORD    0xffff
#define MAX_CMP_WORD	(uint32)0xffffffff

#define CMP_WORD_SIZE	(sizeof (uint32)*BITS_PER_BYTE)
#define ONE        1
#define MINUS_ONE  3

#define HalfWord unsigned short
#define LOW_HALF(x) ((x) & MAX_CMP_HALF_WORD)
#define HIGH_HALF(x) (((x) >> HALF_WORD_BITS) & MAX_CMP_HALF_WORD)
#define TO_HIGH_HALF(x) (((uint32)(x)) << HALF_WORD_BITS)


#define kr_rand(s)	asue_random(s)

long ecc_seed;
#define ecc_rand()	(int)kr_rand(ecc_seed)
#define ecc_srand(s)	do {ecc_seed = (long)s; } while (0)


long ecc_time(long* s)
{
	if (s != NULL)
	{
		*s = (long)(wlan_wapi_iface_get_sys_time() % 0x100000000);
	}
	return (long)(wlan_wapi_iface_get_sys_time() % 0x100000000);
}


/*All SHA functions return one of these values.*/
enum
{
	shaSuccess = 0,
	/*Null pointer parameter*/
	shaNull = 1,
	/*called Input after FinalBits or Result*/
	shaStateError = 3,
};

/*These constants hold size information for each */
/*of the SHA hashing operations*/
enum
{
	SHA256_Message_Block_Size = 64,		SHA256HashSize = 32,
	USHA_Max_Message_Block_Size = 128,	USHAMaxHashSize = 64,
};


/*This structure will hold context information for
the SHA-256 hashing operation.*/
typedef struct SHA256Context
{
	 /*Message Digest*/
	uint32_t Intermediate_Hash[SHA256HashSize/4];
	/*Message length in bits must in front of Length_Low, and neighboring*/
	uint32_t Length_High;
	/*Message length in bits*/
	uint32_t Length_Low;
	/*Message_Block array index 512-bit message blocks*/
	int_least16_t Message_Block_Index;
	uint8_t Message_Block[SHA256_Message_Block_Size];
	/*Is the digest computed?*/
	int Computed;
	/*Is the digest corrupted?*/
	int Corrupted;
} SHA256Context;


/*This structure will hold context information for
the HMAC keyed hashing operation.*/
typedef struct HMACContext
{
	/*hash size of SHA being used*/
	int hashSize;
	/*block size of SHA being used*/
	int blockSize;
	/*SHA context*/
	SHA256Context shaContext;
	/*outer padding - key XORd with opad*/
	unsigned char k_opad[USHA_Max_Message_Block_Size];
} HMACContext;

EllipticCurve TheCurve;
int randseed;


const char *ccpairwise =
"pairwise key expansion for unicast and additional keys and nonce";

const char *cpreshared =
"preshared key expansion for authentication and key negotiation";

const char *cmulticast =
"multicast or station key expansion for station unicast and multicast and broadcast";



/*************************** sha224-256.c ***************************/
/********************* See RFC 4634 for details *********************/
/*Description:This file implements the Secure Hash Signature Standard
algorithms as defined in the National Institute of Standards
and Technology Federal Information Processing Standards Publication
FIPS PUB) 180-1 published on April 17, 1995, 180-2
published on August 1, 2002, and the FIPS PUB 180-2
Change Notice published on February 28, 2004.
A combined document showing all algorithms is available at
http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
The SHA-224 and SHA-256 algorithms produce 224-bit and 256-bit message digests
for a given data stream. It should take about
2**n steps to find a message with the same digest as a given message and
2**(n/2) to find any two messages with the same
digest, when n is the digest size in bits. Therefore, this algorithm can serve
as a means of providing a "fingerprint" for a message.
Portability Issues:SHA-224 and SHA-256 are defined in terms of 32-bit "words".
This code uses <stdint.h> (included via "sha.h") to define 32
and 8 bit unsigned integer types. If your C compiler does not support 32 bit
unsigned integers, this code is not appropriate.
Caveats:SHA-224 and SHA-256 are designed to work with messages less than 2^64
bits long. This implementation uses SHA224/256Input()
to hash the bits that are a multiple of the size of an 8-bit character,
and then uses SHA224/256FinalBits() to hash the final few bits of the input.
*/

#define SHA_Ch(x, y, z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define SHA_Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/*Define the SHA shift, rotate left and rotate right macro*/
#define SHA256_SHR(bits, word)	((word) >> (bits))
#define SHA256_ROTL(bits, word)	(((word) << (bits)) | ((word) >> (32-(bits))))
#define SHA256_ROTR(bits, word)	(((word) >> (bits)) | ((word) << (32-(bits))))


/*Define the SHA SIGMA and sigma macros*/
#define SHA256_SIGMA0(word)	(SHA256_ROTR(2, word) ^ SHA256_ROTR(13,word) ^ \
							SHA256_ROTR(22,word))
#define SHA256_SIGMA1(word)	(SHA256_ROTR(6, word) ^ SHA256_ROTR(11,word) ^ \
							SHA256_ROTR(25,word))
#define SHA256_sigma0(word)	(SHA256_ROTR(7, word) ^ SHA256_ROTR(18,word) ^ \
							SHA256_SHR( 3,word))
#define SHA256_sigma1(word)	(SHA256_ROTR(17, word) ^ SHA256_ROTR(19,word) ^ \
							SHA256_SHR(10,word))


int CanonicalEncode(
	MInt *,
	MInt *
);


/*add "length" to the length*/
static uint32_t addTemp;
#define SHA224_256AddLength(context, length)				\
	(addTemp = (context)->Length_Low, (context)->Corrupted =	\
	(((context)->Length_Low += (length)) < addTemp) &&	\
	(++(context)->Length_High == 0) ? 1 : 0)

static void memcpy_int32_reverse(void* des, const void* src, int n)
{
	int i, j;
	unsigned char *q = (unsigned char *)des;
	const unsigned char *p = (unsigned char *)src;
	for (i = 0; i < n; i++)
		for (j = 0; j < 4; j++)
			q[j + 4 * i] = p[3 - j + 4 * i];
}

EcFpPoint pTable1[POINTTABLELEN];


/*SHA256ProcessMessageBlock, orgin name is SHA224_256ProcessMessageBlock
Description:This function will process the next 512 bits of the message
stored in the Message_Block array.
Parameters:context: [in/out] The SHA context to update
Returns:Nothing.
Comments:Many of the variable names in this code, especially the single
character names, were used because those were the names used in the publication.
*/
static void SHA256ProcessMessageBlock(SHA256Context *context)
{
	/*Constants defined in FIPS-180-2, section 4.2.2*/
	static const uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
		0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
		0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
		0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
		0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
		0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
		0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
		0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
		0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
		0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};
	int t, j, t4;/*Loop counter*/
	uint32_t W[64];/*Word sequence*/
	uint32_t v[8];/*Word buffers*/

	/*Initialize the first 16 words in the array W*/
	for (t = t4 = 0; t < 16; t++, t4 += 4)
		memcpy_int32_reverse(W+t, context->Message_Block+t4, 1);

	for (t = 16; t < 64; t++)
		W[t] = SHA256_sigma1(W[t-2]) + W[t-7] + SHA256_sigma0(W[t-15])
			+ W[t-16];

	memcpy(v, context->Intermediate_Hash, 8*sizeof(v[0]));
	for (t = 0; t < 64; t++)
	{
		uint32_t t1 = v[7] + SHA256_SIGMA1(v[4])
					+ SHA_Ch(v[4], v[5], v[6])
					+ K[t] + W[t];
		uint32_t t2 = SHA256_SIGMA0(v[0])
					+ SHA_Maj(v[0], v[1], v[2]);
		for (j = 0; j < 7; j++)
		{
			v[7-j] = v[6-j];
		}
		v[4] += t1;
		v[0] = t1 + t2;
	}
	for (j=0; j<8; j++)
	{
		context->Intermediate_Hash[j] += v[j];
	}
	context->Message_Block_Index = 0;
}




/*SHA256Reset
Description:This function will initialize the SHA256Context in preparation
for computing a new SHA256 message digest.
Parameters:context: [in/out] The context to reset.
Returns:sha Error Code.
*/
static int SHA256Reset(SHA256Context *context)
{
	static uint32_t SHA256_H0[SHA256HashSize/4] = {0x6A09E667, 0xBB67AE85,
			0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
			0x1F83D9AB, 0x5BE0CD19};
	if (!context)
		return shaNull;

	memset(context, 0, sizeof(SHA256Context));
	memcpy(context->Intermediate_Hash, SHA256_H0, 8*sizeof(uint32_t));
	return shaSuccess;
}

/*SHA256Input
Description:This function accepts an array of octets as the next
portion of the message.
Parameters:context: [in/out] The SHA context to update
message_array: [in] An array of characters representing the next
portion of the message.
length: [in] The length of the message in message_array
Returns:sha Error Code.
*/
static int SHA256Input(SHA256Context *context, const uint8_t *message_array,
			unsigned int length)
{
	if (!length)
		return shaSuccess;
	if (!context || !message_array)
		return shaNull;
	if (context->Computed)
	{
		context->Corrupted = shaStateError;
		return shaStateError;
	}
	if (context->Corrupted)
		return context->Corrupted;
	while (length-- && !context->Corrupted)
	{
		context->Message_Block[context->Message_Block_Index++]
						= (*message_array & 0xFF);
		if (!SHA224_256AddLength(context, 8) &&
		(context->Message_Block_Index == SHA256_Message_Block_Size))
			SHA256ProcessMessageBlock(context);
		message_array++;
	}
	return shaSuccess;
}

/*SHA256Result
Description:This function will return the 256-bit message digest
into the Message_Digest array provided by the caller.
NOTE: The first octet of hash is stored in the 0th element,
the last octet of hash in the 32nd element.
Parameters:context: [in/out] The context to use to calculate the SHA hash.
Message_Digest: [out] Where the digest is returned.
Returns:sha Error Code.
*/
static int SHA256Result(SHA256Context *context, uint8_t Message_Digest[])
{
	int i;
	int HashSize = SHA256HashSize;

	if (!context || !Message_Digest)
		return shaNull;

	if (context->Corrupted)
		return context->Corrupted;

	if (!context->Computed)
	{/*SHA224_256Finalize(context, 0x80);*/
		uint8_t Pad_Byte = 0x80;
		{/*SHA224_256PadMessage(context, Pad_Byte);*/
			/*Check to see if the current message block is too
			small to hold the initial padding bits and length.
			If so, we will pad the block, process it, and then
			continue padding into a second block.*/
			if (context->Message_Block_Index >=
				(SHA256_Message_Block_Size-8))
			{
				context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
				while (context->Message_Block_Index < SHA256_Message_Block_Size)
					context->Message_Block[context->Message_Block_Index++] = 0;
				SHA256ProcessMessageBlock(context);
			}
			else
				context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

			while (context->Message_Block_Index < (SHA256_Message_Block_Size-8))
				context->Message_Block[context->Message_Block_Index++] = 0;

			/*Store the message length as the last 8 octets*/
			memcpy_int32_reverse(context->Message_Block+56,
				&context->Length_High, 2);

			SHA256ProcessMessageBlock(context);
		}

		/*message may be sensitive, so clear it out*/
		memset(context->Message_Block, 0, SHA256_Message_Block_Size);
		context->Length_Low = context->Length_High = 0;/*and clear length*/
		context->Computed = 1;
	}

	for (i = 0; i < HashSize; ++i)
		Message_Digest[i] =
		(uint8_t)(context->Intermediate_Hash[i>>2] >> 8 * (3 - (i & 0x03)));

	return shaSuccess;
}

int mhash_sha256_base(unsigned char* d, unsigned l, unsigned char* o)
{
	SHA256Context ctx;
	return SHA256Reset(&ctx) || SHA256Input(&ctx, d, l) || SHA256Result(&ctx, o);
}


/**************************** hmac.c ****************************/
/******************** See RFC 4634 for details ******************/
/*Description:This file implements the HMAC algorithm
(Keyed-Hashing for Message Authentication, RFC 2104), expressed in terms of
the various SHA algorithms.*/

/*hmacReset
Description:This function will initialize the hmacContext in preparation
for computing a new HMAC message digest.
Parameters:context: [in/out] The context to reset.
key: [in] The secret shared key.
key_len: [in] The length of the secret shared key.
Returns:sha Error Code.
*/
static int hmacReset(HMACContext* ctx, const unsigned char *key, int key_len)
{
	int i, blocksize, hashsize;
	/*inner padding - key XORd with ipad*/
	unsigned char k_ipad[USHA_Max_Message_Block_Size];
	/*temporary buffer when keylen > blocksize*/
	unsigned char tempkey[USHAMaxHashSize];
	if (!ctx)
		return shaNull;

	blocksize = ctx->blockSize = SHA256_Message_Block_Size;
	hashsize = ctx->hashSize = SHA256HashSize;
	/*If key is longer than the hash blocksize,
	reset it to key = HASH(key).*/
	if (key_len > blocksize)
	{
		SHA256Context tctx;
		int err = SHA256Reset(&tctx) || SHA256Input(&tctx, key, key_len)
						|| SHA256Result(&tctx, tempkey);
		if (err != shaSuccess)
			return err;

		key = tempkey;
		key_len = hashsize;
	}
	/*The HMAC transform looks like:SHA(K XOR opad, SHA(K XOR ipad, text)),
	where K is an n byte key. ipad is the byte 0x36 repeated blocksize
	times opad is the byte 0x5c repeated blocksize times and text
	is the data being protected.*/
	for (i = 0; i < key_len; i++)
	{/*store key into the pads, XOR'd with ipad and opad values*/
		k_ipad[i] = key[i] ^ 0x36;
		ctx->k_opad[i] = key[i] ^ 0x5c;
	}
	for ( ; i < blocksize; i++)
	{/*remaining pad bytes are '\0' XOR'd with ipad and opad values*/
		k_ipad[i] = 0x36;
		ctx->k_opad[i] = 0x5c;
	}
	/*perform inner hash*/ /*init context for 1st pass*/
	/*and start with inner pad*/
	return SHA256Reset(&ctx->shaContext) || SHA256Input(&ctx->shaContext,
							k_ipad, blocksize);
}

static int hmacResult(HMACContext *ctx, uint8_t *digest)
{
	if (!ctx)
		return shaNull;
	/*finish up 1st pass*/ /*(Use digest here as a temporary buffer.)*/
	return SHA256Result(&ctx->shaContext, digest)
		|| SHA256Reset(&ctx->shaContext)
		|| SHA256Input(&ctx->shaContext, ctx->k_opad, ctx->blockSize)
		|| SHA256Input(&ctx->shaContext, digest, ctx->hashSize)
		|| SHA256Result(&ctx->shaContext, digest);
}


static int hmac(const unsigned char* text, int text_len,
const unsigned char *key, int key_len, uint8_t digest[USHAMaxHashSize])
{
	HMACContext ctx;
	return hmacReset(&ctx, key, key_len)
	|| SHA256Input(&ctx.shaContext, text, text_len)
	|| hmacResult(&ctx, digest);
}


/*HMACResult
Description:This function will return the N-byte message digest into the
Message_Digest array provided by the caller.
NOTE: The first octet of hash is stored in the 0th element, the last
octet of hash in the Nth element.
Parameters:context: [in/out] The context to use to calculate the HMAC hash.
digest: [out] Where the digest is returned.
NOTE 2: The length of the hash is determined by the value of whichSha
that was passed to hmacReset().
Returns:sha Error Code.
*/



int wapi_hmac_sha256(unsigned char* t, int tl, unsigned char* k, unsigned kl,
				unsigned char* o, unsigned ol)
{
	unsigned char tmp[USHAMaxHashSize] = {0};
	int ret = hmac(t, tl, k, kl, tmp);
	if (0 == ret)	memcpy(o, tmp, ol);
	return 0 == ret;
}


void KD_hmac_sha256(unsigned char* t, unsigned tl, unsigned char* k, unsigned kl,
			unsigned char* o, unsigned ol)
{
	unsigned i;
	unsigned length = ol;
	unsigned SHA256_DIGEST_SIZE = SHA256HashSize;
	for (i = 0; length/SHA256_DIGEST_SIZE; i++, length-=SHA256_DIGEST_SIZE)
	{
		wapi_hmac_sha256(t, tl, k, kl, &o[i*SHA256_DIGEST_SIZE],
				SHA256_DIGEST_SIZE);
		t = &o[i*SHA256_DIGEST_SIZE];
		tl = SHA256_DIGEST_SIZE;
	}
	if (length > 0)
		wapi_hmac_sha256(t, tl, k, kl, &o[i*SHA256_DIGEST_SIZE], ol);
}


int mhash_sha256_contx(const CONTX *contx, unsigned length,
		unsigned char* digest,unsigned digest_length)
{
	unsigned char tmp[USHAMaxHashSize] = {0};
	int ret = mhash_sha256_base(contx->buff, contx->length, tmp);
	if (0 == ret)
		memcpy(digest, tmp, digest_length);
	return 0 == ret;
}

void prf_preshared(const unsigned char* key, unsigned keylen,
		unsigned char* keyout)
{
	prf_hmac_sha256((unsigned char*)cpreshared, (int)strlen(cpreshared),
			(unsigned char*)key, keylen, keyout, 16);
}


void prf_pairkey96(const unsigned char* key, unsigned char* buffer,
			unsigned bufferlen, unsigned char* keyout)
{
	int len = 0;
	unsigned char pChar[2048] = {0};
	len = (int)strlen(ccpairwise);
	memcpy(pChar, buffer, bufferlen);
	memcpy(pChar+bufferlen, ccpairwise, len);
	prf_hmac_sha256(pChar, len + bufferlen, (unsigned char*)key, 16,
			keyout, 96);
}

void prf_multikey32(const unsigned char* key, unsigned char* keyout)
{
	prf_hmac_sha256((unsigned char*)cmulticast, (int)strlen(cmulticast),
			(unsigned char*)key, 16, keyout, 32);
}


void sha256_digest_int(const void *msg, unsigned len, MInt *d)
{
	unsigned char tmp[64] = {0};
	unsigned i;
	mhash_sha256_base((unsigned char*)msg, len, tmp);

	for (i = 0; i < 8; i++)
	{
		unsigned char* p = tmp + 4*i;
		d->value[7-i] = (p[0]<<24) + (p[1]<<16) + (p[2]<<8) + p[3];
	}
	d->length = 8;
}


int MI_Move (MInt *source,MInt *destination)
{
	int i;
	destination->length = source->length;
	for(i = 0; i < source->length; i++)
		destination->value[i] = source->value[i];
	return 0;
}


int MI_Compare (MInt *firstMInt, MInt *secondMInt)
{
	int i;

	if (firstMInt->length > secondMInt->length)
	{
		if ((firstMInt->length == 1) && (firstMInt->value[0] == 0))
			return 0;
		else
			return 1;
	}
	else if (firstMInt->length < secondMInt->length)
	{
		if ((secondMInt->length == 1) && (secondMInt->value[0] == 0))
			return 0;
		else
			return -1;
  }
	else {
		for (i = firstMInt->length - 1; i >= 0; --i)
			if (firstMInt->value[i] > secondMInt->value[i])
				return 1;
			else if (firstMInt->value[i] < secondMInt->value[i])
				return -1;
	}
	return 0;
}


int MI_Add (MInt *addend1,MInt *addend2,MInt *sum)
{
	uint32 *a, carry, *longValue, *shortValue, word;
	int i, max, min;

	if (addend1->length > addend2->length)
	{
		max = addend1->length;
		min = addend2->length;
		longValue = addend1->value;
		shortValue = addend2->value;
	}
	else {
		min = addend1->length;
		max = addend2->length;
		longValue = addend2->value;
		shortValue = addend1->value;
	}
	do {
		carry = 0;
		a = sum->value;
		for (i = 0; i < min; ++ i)
		{
			if ((word = longValue[i] + carry) < carry) {
			carry = 1;
			word = shortValue[i];
		}
		else if ((word += shortValue[i]) < shortValue[i])
			carry = 1;
		else
			carry = 0;
		a[i] = word;
	}
	for (i = min; i < max; ++ i)
		if ((a[i] = carry + longValue[i]) < carry)
			carry = 1;
		else
		{
			carry = 0;
			++i;
			memcpy (&a[i], &longValue[i],
			sizeof (uint32) * (max - i));
			break;
		}
	if (carry == 1) {
		a[max] = 1;
		sum->length = max + 1;
	}
	else
		sum->length = max;
	} while (0);

	return 0;
}


int MI_Subtract (MInt *minuend, MInt *subtrahend, MInt *difference)
{
	MInt  *b, *c;
	uint32 ai, borrow;
	int i, status=0;

	do
	{
		if ((i = MI_Compare (minuend, subtrahend)) > 0)
		{
			b = minuend;
			c = subtrahend;
		}
		else if (i == 0) {
			difference->length = 1;
			difference->value[0] = 0;
			break;
		}
		else {
			b = subtrahend;
			c = minuend;
			status = MI_NEGATIVE;
		}
	borrow = 0;
	for (i = 0; i < c->length ; ++ i)
	{
		if ((borrow += c->value[i]) < c->value[i])
		{
			difference->value[i] = b->value[i];
			borrow = 1;
		}
		else
		{
			if ((ai = b->value[i] - borrow) >
			(MAX_CMP_WORD - borrow))
				borrow = 1;
			else
				borrow = 0;
		difference->value[i] = ai;
		}
	}

	for (i = c->length;i < b->length; ++ i) {
		if ((ai = b->value[i] - borrow) > MAX_CMP_WORD - borrow)
			borrow = 1;
		else
			borrow = 0;
	difference->value[i] = ai;
	}
	MI_RecomputeLength(b->length , difference);
	} while (0);

	return (status);
}


void DWordMult (uint32 a[2], const uint32 b, const uint32 c)
{
	register uint32 t, u;
	HalfWord bHigh, bLow, cHigh, cLow;

	bHigh = (HalfWord)HIGH_HALF (b);
	bLow = (HalfWord)LOW_HALF (b);
	cHigh = (HalfWord)HIGH_HALF (c);
	cLow = (HalfWord)LOW_HALF (c);

	a[0] = (uint32)bLow * (uint32)cLow;
	t = (uint32)bLow * (uint32)cHigh;
	u = (uint32)bHigh * (uint32)cLow;
	a[1] = (uint32)bHigh * (uint32)cHigh;

	if ((t += u) < u)
		a[1] += TO_HIGH_HALF (1);
	u = TO_HIGH_HALF (t);

	if ((a[0] += u) < u)
		++a[1];
	a[1] += HIGH_HALF (t);
}


int MI_Multiply(MInt *multiplicand, MInt *multiplier, MInt *product)
{
	uint32 a[MINTLENGTH], *b, *c;
	int cLen, i, productLen;

	productLen = multiplicand->length + multiplier->length;
	if (MINTLENGTH < productLen)
		return (-1);

	b = multiplicand->value;
	c = multiplier->value;
	cLen = multiplier->length;
	for(i = 0; i < productLen; i++)
		a[i] = 0;;
	for (i = 0; i < multiplicand->length; ++ i)
		a[cLen + i] += DW_AddProduct (&a[i], &a[i], b[i], c, cLen);
	for(i = 0; i < productLen; i++)
		product->value[i] = a[i];
	MI_RecomputeLength (productLen, product);

	return 0;
}

static uint32 CMP_ArraySub (uint32 *a, uint32 *b, uint32 *c,
				unsigned int length)
{
	uint32 ai, borrow;
	unsigned int i;

	borrow = 0;
	for (i = 0; i < length; ++ i) {
		if ((borrow += c[i]) < c[i]) {
			a[i] = b[i];
			borrow = 1;
		}
	else {
		if ((ai = b[i] - borrow) > (MAX_CMP_WORD - borrow))
			borrow = 1;
		else
			borrow = 0;
		a[i] = ai;
	}
	}
	return borrow;
}


static uint32 CMP_ArrayLeftShift (uint32 *a, unsigned int bits,
				unsigned int length)
{
	uint32 r, shiftOut;
	unsigned int i, bitsLeft;

	if (bits == 0) {
		return 0;
	}

	bitsLeft = CMP_WORD_SIZE - bits;
	shiftOut = 0;
	for (i = 0; i < length; ++i) {
		r = a[i];
		a[i] = (r << bits) | shiftOut;
		shiftOut = r >> bitsLeft;
	}
	return shiftOut;
}


static uint32 CMP_ArrayRightShift (uint32 *a, unsigned int bits,
				unsigned int length)
{
	uint32 r, shiftOut;
	int i, bitsLeft;

	if (bits == 0) {
		return 0;
	}

	bitsLeft = CMP_WORD_SIZE - bits;
	shiftOut = 0;
	for (i = length - 1; i >= 0; --i) {
		r = a[i];
		a[i] = (r >> bits) | shiftOut;
		shiftOut = r << bitsLeft;
	}
	return shiftOut;
}



void CMP_WordDiv (uint32 *a, uint32 b[2], uint32 c)
{
	uint32 t[2], u, v;
	HalfWord aHigh, aLow, cHigh, cLow;

	cHigh = (HalfWord)( (c >>16) & 0xffff);
	cLow = (HalfWord)( (c&0xffff));

	t[0] = b[0];
	t[1] = b[1];

	if (cHigh == MAX_CMP_HALF_WORD)
		aHigh = (HalfWord)HIGH_HALF (t[1]);
	else
		aHigh = (HalfWord)(t[1] / (cHigh + 1));
	u = (uint32)aHigh * (uint32)cLow;
	v = (uint32)aHigh * (uint32)cHigh;
	if ((t[0] -= TO_HIGH_HALF (u)) > (MAX_CMP_WORD - TO_HIGH_HALF (u)))
		-- t[1];
	t[1] -= HIGH_HALF (u);
	t[1] -= v;

	while ((t[1] > cHigh) ||
		((t[1] == cHigh) && (t[0] >= TO_HIGH_HALF (cLow)))) {
		if ((t[0] -= TO_HIGH_HALF (cLow)) >
		MAX_CMP_WORD - TO_HIGH_HALF (cLow))
			-- t[1];
	t[1] -= cHigh;
	++ aHigh;
	}

	if (cHigh == MAX_CMP_HALF_WORD)
		aLow = (HalfWord)LOW_HALF (t[1]);
	else
		aLow = (HalfWord)(
		(TO_HIGH_HALF (t[1]) + HIGH_HALF (t[0])) / (cHigh + 1));
	u = (uint32)aLow * (uint32)cLow;
	v = (uint32)aLow * (uint32)cHigh;
	if ((t[0] -= u) > (MAX_CMP_WORD - u))
		-- t[1];
	if ((t[0] -= TO_HIGH_HALF (v)) > (MAX_CMP_WORD - TO_HIGH_HALF (v)))
		-- t[1];
	t[1] -= HIGH_HALF (v);

	while ((t[1] > 0) || ((t[1] == 0) && t[0] >= c)) {
		if ((t[0] -= c) > (MAX_CMP_WORD - c))
			-- t[1];
	++ aLow;
	}

	*a = TO_HIGH_HALF (aHigh) + aLow;
}


static uint32 CMP_SubProduct (uint32 *a, uint32 *b, uint32 c,
					uint32 *d, unsigned int length)
{
	uint32 borrow, t[2];
	unsigned int i;

	borrow = 0;
	for (i = 0; i < length; ++ i)
	{
		DWordMult (t, c, d[i]);

	if ((borrow += t[0]) < t[0])
		++ t[1];
	if ((a[i] = b[i] - borrow) > (MAX_CMP_WORD - borrow))
		borrow = t[1] + 1;
	else
		borrow = t[1];
	}
	return borrow;
}


static int CMP_ArrayCmp (uint32 *a, uint32 *b, unsigned int length)
{
	int i;

	for (i = (int)length - 1; i >= 0; -- i) {
		if (a[i] > b[i])
			return 1;
		else if (a[i] < b[i])
			return -1;
	}
	return (0);
}


int MI_Divide (MInt *dividend, MInt *divisor,
			   MInt *quotient, MInt *remainder)
{
	uint32 ai, t, *aa, *cc, *dd;
	uint32 a;
	int i;
	unsigned int ccWords, ddWords, shift;

	MI_RecomputeLength (dividend->length,dividend);
	MI_RecomputeLength (divisor->length,divisor);

	do
	{
		if (MI_Compare (dividend, divisor) < 0)
		{
			MI_WordToMInt (0, quotient);
			MI_Move (dividend, remainder);
			break;
		}

		MI_Move(dividend, remainder);

		a=divisor->value[divisor->length-1];
		for(i=0;(i<CMP_WORD_SIZE)&&(a!=0);++i,a>>=1);

		shift = CMP_WORD_SIZE - i;
		ccWords = remainder->length;
		cc = remainder->value;
		if ((cc[ccWords] =
		CMP_ArrayLeftShift (cc, shift, ccWords)) != 0)
			cc[++ ccWords] = 0;

		ddWords = divisor->length;
		dd = divisor->value;
		CMP_ArrayLeftShift (dd, shift, ddWords);
		t = dd[ddWords - 1];
		aa = quotient->value;

		for (i = ccWords - ddWords; i >= 0; -- i)
		{
			if (t == MAX_CMP_WORD)
				ai = cc[i + ddWords];
			else
				CMP_WordDiv (&ai, &cc[i + ddWords - 1], t + 1);
			cc[i + ddWords] -= CMP_SubProduct (&cc[i], &cc[i], ai,
						dd, ddWords);

			while (cc[i + ddWords] || (CMP_ArrayCmp (&cc[i], dd,
			ddWords) >= 0)) {
				++ ai;
				cc[i + ddWords] -= CMP_ArraySub (&cc[i], &cc[i],
						dd, ddWords);
			}
			aa[i] = ai;
		}

		CMP_ArrayRightShift (dd, shift, ddWords);
		CMP_ArrayRightShift (cc, shift, ddWords);
		MI_RecomputeLength (ddWords, remainder);
		MI_RecomputeLength (ccWords - ddWords + 1, quotient);
	} while (0);

	return 0;
}

int FP_Add (MInt *addend1, MInt *addend2,
		MInt *modulus, MInt *sum)
{
	MInt t;
	MI_Add (addend1, addend2, &t);
	if (MI_Compare (&t, modulus) >= 0)
		MI_Subtract (&t, modulus, sum);
	else
		MI_Move (&t, sum);
	return 0;
}


int FP_Substract (MInt *minuend, MInt *subtrahend,
		MInt *modulus, MInt *difference)
{
	MInt  t;
	int status;
	status = MI_Subtract (minuend, subtrahend, &t);
	if (status == 0)
		MI_Move (&t, difference);
	else
		MI_Subtract (modulus, &t, difference);
    return 0;

}


int FP_Invert (MInt *operand, MInt *modulus, MInt *inverse)
{
	MInt q, t1, t3, u1, u3, v1, v3, w;
	int u1Sign;
	MI_WordToMInt (1, &u1);
	MI_WordToMInt (0, &v1);
	MI_Move (operand, &u3);
	MI_Move (modulus, &v3);

	u1Sign = 1;
	while (v3.length != 0 )
	{
		MI_Divide (&u3, &v3, &q, &t3);
		MI_Multiply (&q, &v1, &w);
		MI_Add (&u1, &w, &t1);
		MI_Move (&v1, &u1);
		MI_Move (&t1, &v1);
		MI_Move (&v3, &u3);
		MI_Move (&t3, &v3);
		u1Sign = -u1Sign;
	}

	if (u1Sign < 0)
		MI_Subtract (modulus, &u1, inverse);
	else
		MI_Move (&u1, inverse);

	return 0;
}

static int FpDivByTwo(MInt *a, MInt *p)
{
	int len, i;
	uint32 *av, shifth, shiftl;
	av = a->value;
	len = a->length;
	shifth = 0;
	if (av[0] == ((av[0]>>1)<<1))
	{
		if (av[len-1] == 1)
			a->length=len-1;
		for (i = len-1; i >= 0; i--)
		{
			shiftl = av[i] - ((av[i]>>1)<<1);
			av[i] = (shifth<<31) + (av[i]>>1);
			shifth = shiftl;
		}
	}
	else
	{
		MI_Add(a, p, a);
		len = a->length;
		if (av[len-1] == 1)
			a->length = len - 1;
		for (i = len-1; i >= 0; i--)
		{
			shiftl = av[i] - ((av[i]>>1)<<1);
			av[i] = (shifth<<31) + (av[i]>>1);
			shifth = shiftl;
		}
	}
	return 0;
}


int (* FpMul)(MInt *, MInt *, MInt *, MInt *);

int FP_Mul(MInt *multiplicand, MInt *multiplier, MInt *p, MInt *prod)
{
	return (* FpMul)(multiplicand, multiplier, p, prod);
}


int FpMinus (MInt *operand, MInt *prime, MInt *result)
{
	if (operand->length == 1 && operand->value[0] == 0)
		FP_Move (operand, result);
	else
		MI_Subtract (prime, operand, result);
	return 0;
}


int JointSFKL_Encode(MInt *k, MInt *l, unsigned char *JSF)
{
	unsigned char d0, d1, temp0, temp1, jsfk, jsfl;
	int  i, index;
	MInt k1, l1;
	MI_Move(k, &k1);
	MI_Move(l, &l1);

	d0 = 0;
	d1 = 0;
	index = 0;
	while (k->length || l->length || d0 || d1){
		temp0 = (k->value[0] + d0)&7;
		temp1 = (l->value[0] + d1)&7;

		if (!(temp0&01))
			jsfk=0;
		else{
			jsfk=temp0&03;
			if(((temp1&3)==2)&&(((temp0&7)==3)||((temp0&7)==5)))
				jsfk=(jsfk+2)&3;
		}

		if (!(temp1&01))
			jsfl=0;
		else{
			jsfl = temp1&03;
			if(((temp0&3)==2)&&(((temp1&7)==3)||((temp1&7)==5)))
				jsfl=(jsfl+2)&3;
		}
		JSF[index]=(((jsfk+1)>>1)*3+((jsfl+1)>>1));

		if(((1+jsfk)&3)==(2*d0)) d0=1-d0;
		if(((1+jsfl)&3)==(2*d1)) d1=1-d1;

		i = k->length-1;
		if(k->value[i]==1)
			k->length--;
		temp0 = 0;
		for(; i >= 0; i--){
			temp1=k->value[i]&01;
			k->value[i]=(k->value[i]>>1)|(temp0<<31);
			temp0 = temp1;
		}
		i = l->length-1;
		if(l->value[i] == 1)
			l->length--;
		temp0 = 0;
		for(; i >= 0; i--){
			temp1 = l->value[i]&01;
			l->value[i] = (l->value[i]>>1)|(temp0<<31);
			temp0 = temp1;
		}
		index++;
	 }
	MI_Move(&k1,k);
	MI_Move(&l1,l);

	return index;
}


int ECFpKTimes (EcFpPoint *operand, MInt *k, MInt *a, MInt *b,
				MInt *prime, EcFpPoint *result)
{
	EcFpPointProject rr;
	EcFpPoint pp, qq;
	MInt inverse, kk,temp;
	uint32 s, t;
	int i, j, kkWords;
	unsigned int bits;
	if(FP_IsZero(k))
	{
		result->isInfinite = 1;
		return 0;
	}
	MI_WordToMInt (0, &rr.x);
	MI_WordToMInt (1, &rr.y);
	MI_WordToMInt (0, &rr.z);

	CanonicalEncode (k, &kk);

	kkWords = kk.length;
	FP_Move (&operand->x, &pp.x);
	FP_Move (&operand->y, &pp.y);

	FP_Move (&operand->x, &qq.x);
	FpMinus (&operand->y, prime, &qq.y);

	for (i = kkWords - 1; i >= 0; -- i)
	{
		t = kk.value[i];
		bits = MI_WORD_SIZE;
		if (i == kkWords - 1)
		{
			while (! (t>>(MI_WORD_SIZE-2)))
			{
				t <<= 2;
				bits -= 2;
			}
		}
		for (j = bits; j > 0; j -= 2, t <<= 2)
		{
			ECFpDoubleProj (&rr, a, b, prime, &rr);
			if ((s = (t>>(MI_WORD_SIZE-2)))==ONE)
				ECFpAddProj (&rr, &pp, a, b, prime, &rr);
			else if (s == MINUS_ONE)
				ECFpAddProj (&rr, &qq, a, b, prime, &rr);
		}
	}

	if (FP_IsZero (&rr.z))
		result->isInfinite = 1;
	else
	{
		result->isInfinite = 0;
		FP_Invert (&rr.z, prime, &inverse);
		FPSqr_Mul (&inverse, prime, &temp);
		FP_Mul (&rr.x, &temp, prime, &result->x);
		FP_Mul(&temp,&inverse,prime,&inverse);
		FP_Mul (&rr.y, &inverse, prime, &result->y);
	}

	return 0;
}

int PointToEcFpPoint(const Point *sour, EcFpPoint *dest )
{
	int i;
	for (i = PARABUFFER-1; i >= 0; i--)
		if (sour->x[i] != 0)
			break;
	dest->x.length = i + 1;
	for (; i >= 0; i--)
		dest->x.value[i] = sour->x[i];

	for (i = PARABUFFER-1; i >= 0; i--)
		if (sour->y[i] != 0)
			break;
	dest->y.length = i + 1;
	for(; i >= 0; i--)
		dest->y.value[i] = sour->y[i];

	if((dest->x.length == 0)&&(dest->y.length == 0))
		dest->isInfinite = 1;
	else
		dest->isInfinite = 0;

	return 0;
}


int MIntToOctetString (MInt *srcInt, unsigned int OSBufferSize,
		unsigned int *OSLen, unsigned char *DString)
{
	uint32 word;
	int i, j, k, status, t;

	status = 0;
	do
	{
		for (i = srcInt->length - 1, j = 0; i >= 0; -- i)
	{
		t = MI_BYTES_PER_WORD;
		word = srcInt->value[i];
		if (i == srcInt->length - 1)
		{
			while ((word>>((t-1)*MI_BITS_PER_BYTE)==0)&&(t>1))
			-- t;
			if(t+i*MI_BYTES_PER_WORD>OSBufferSize)
			{
				status = OUTPUT_SIZE;
				break;
			}
		}
		for (k = t - 1; k >= 0; -- k)
			DString[j ++] = (unsigned char)(srcInt->value[i]>>
					(k*MI_BITS_PER_BYTE));
	}
	if (status == 0)
		*OSLen = j;
	} while (0);

	return (status);
}

int MIntToFixedLenOS(MInt *srcInt,unsigned int fixedLength,
				unsigned int OSBufferSize, unsigned int *OSLen,
				unsigned char *DString)
{
	int d, i, status;
	unsigned int len;

	do
	{
	if ((status = MIntToOctetString (srcInt, OSBufferSize,
	&len, DString)) != 0)
	break;
	if ((d = fixedLength - len) > 0)
	{
		for (i = fixedLength - 1; i >= d; -- i)
			DString[i] = DString[i - d];
		for (i = d - 1; i >= 0; -- i)
			DString[i] = 0;
	}
	else if (d < 0)
	{
		status = OUTPUT_LEN;
		break;
	}
	*OSLen = fixedLength;
	} while (0);

	return (status);
}

int GenRandomNumber (MInt *theInt, MInt *maxInt)
{
	int j, k, aa;
	MInt t;
	unsigned int ss = 1;
	ecc_srand((unsigned)ecc_time(NULL));

	t.length = maxInt->length ;

	for(j = 0;j < maxInt->length ;j++)
	{
		for(k = 0; k < 3; k++)
	{

	aa = ecc_rand()+randseed+(randseed<<1)+(randseed>>1);
	randseed++;
	ss = ss|(aa<<k*11);
	}
	t.value[j] = ss;
	ss = 1;
	}
	MI_ModularReduce (&t, maxInt,theInt);

	return 0;
}

uint32 C_TABLE1[8] = { 0, 0, 0, 4, 0, 4, 4, 4 },
C_TABLE2[8] = {0, 1, 0, 3, 1, 0, 3, 0 };
int CanonicalEncode (MInt *source, MInt *destination)
{
	uint32 word, srcWord;
	int ci, entry, i, j, wordBits, words;

	words = source->length;
	ci = 0;
	wordBits = sizeof (uint32) * 8;
	for (i = 0; i < words; ++ i)
	{
		word = 0;
		srcWord = source->value[i];
		for (j = 0; j < wordBits / 2; ++ j)
		{
			entry = ci | (unsigned int)((srcWord >> j) & 3);
			ci = (int)C_TABLE1[entry];
			word |= (C_TABLE2[entry] << (2 * j));
		}
		destination->value[2 * i] = word;
		word = 0;
		for (j = MI_WORD_SIZE / 2; j < wordBits - 1; ++ j)
		{
			entry = ci | (unsigned int)((srcWord >> j) & 3);
			ci = (int)C_TABLE1[entry];
			word |= (C_TABLE2[entry] << (2 * j - MI_WORD_SIZE));
		}
		entry = ci | (unsigned int)(srcWord >> (wordBits - 1));
		entry = (i == words - 1) ? entry :
			entry | (unsigned int)((source->value[i + 1] << 1) & 2);
		ci = (int)C_TABLE1[entry];
		word |= (C_TABLE2[entry] << (MI_WORD_SIZE - 2));
		destination->value[2 * i + 1] = word;
	}
	if (ci != 0)
		destination->value[2 * i] = 1;
	else
		destination->value[2 * i] = 0;
	MI_RecomputeLength (2 * words + 1, destination);

	return 0;
}



int ECFpAdd (EcFpPoint *addend1, EcFpPoint *addend2,
			 MInt *a, MInt *b,MInt *prime,EcFpPoint *sum)
{
	MInt r, s, t;
	if (addend1->isInfinite == 1)
	{
		sum->isInfinite = addend2->isInfinite;
		FP_Move (&addend2->x, &sum->x);
		FP_Move (&addend2->y, &sum->y);
		return 0;
	}
	else if (addend2->isInfinite == 1)
	{
		sum->isInfinite = addend1->isInfinite;
		FP_Move (&addend1->x, &sum->x);
		FP_Move (&addend1->y, &sum->y);
		return 0;
	}
	else if (FP_Equal (&addend1->x, &addend2->x))
	{
		FP_Substract (prime, &addend2->y, prime, &r);
		if (FP_Equal (&addend1->y, &r))
		{
			sum->isInfinite = 1;
			return 0;
		}
		else if (FP_Equal (&addend1->y, &addend2->y))
		{
			FPSqr_Mul (&addend1->x,prime, &r);
			FP_Add (&r, &r, prime, &t);
			FP_Add (&r, &t, prime, &s);
			FP_Add (&s, a, prime, &r);
			FP_Add (&addend1->y, &addend1->y, prime, &t);
			FP_Invert (&t, prime, &s);
			FP_Mul (&s, &r, prime, &t);
			FPSqr_Mul(&t,prime, &r);
			FP_Substract (&r, &addend1->x, prime, &s);
			FP_Substract (&s, &addend2->x, prime, &r);
			FP_Substract (&addend1->x, &r, prime, &s);
			FP_Move (&r, &sum->x);
			FP_Mul (&t, &s, prime, &r);
			FP_Substract (&r, &addend1->y, prime, &sum->y);

			return 0;
		}
	}
	FP_Substract (&addend2->x, &addend1->x, prime, &t);
	FP_Substract (&addend2->y, &addend1->y, prime, &s);
	FP_Invert (&t, prime, &r);
	FP_Mul (&s, &r, prime, &t);
	FPSqr_Mul (&t, prime, &r);
	FP_Substract (&r, &addend1->x, prime, &s);
	FP_Substract (&s, &addend2->x, prime, &r);
	FP_Substract (&addend1->x, &r, prime, &s);
	FP_Move (&r, &sum->x);
	FP_Mul (&t, &s, prime, &r);
	FP_Substract (&r, &addend1->y, prime, &sum->y);
	sum->isInfinite = 0;

	return 0;
}


int PubKeyToOctetString(Point *poPublicKey, unsigned int OSBuffSize,
			unsigned int *OSLen, unsigned char *DString)
{
	MInt x, y;
	int i;
	unsigned int len;
	for (i = PARABUFFER-1; i >= 0; i--)
		if (poPublicKey->x[i] != 0)
			break;
	x.length = i + 1;
	for(; i >= 0; i--)
		x.value[i] = poPublicKey->x[i];

	for(i = PARABUFFER-1; i >= 0; i--)
		if(poPublicKey->y[i] != 0)
			break;
	y.length = i + 1;
	for(; i >= 0; i--)
		y.value[i] = poPublicKey->y[i];

	MIntToFixedLenOS(&x, PARABUFFER*4, OSBuffSize, &len, DString);
	MIntToFixedLenOS(&y, PARABUFFER*4, OSBuffSize, OSLen, DString+len);
	*OSLen += len;

	return 0;
}


int ECFpKTimes_FixP (EcFpPoint *operand,EcFpPoint *Table1,
				 MInt *k,MInt *a,MInt *b,
				MInt *prime, EcFpPoint *result)
{
	EcFpPointProject rr;
	MInt inverse, temp;

	int i, j, m, e, length;
	unsigned int t, t2, ki, ki2;

	if(FP_IsZero(k))
	{
		result->isInfinite = 1;
		return 0;
	}
	length = 1<<(prime->length);

	MI_WordToMInt (0, &rr.x);
	MI_WordToMInt (1, &rr.y);
	MI_WordToMInt (0, &rr.z);

	e = 16;
	for(i = e; i > 0; i--)
	{

		ECFpDoubleProj (&rr, a, b, prime, &rr);
		t = 0; t2 = 0;
		for (j = 0; j < k->length; j++)
		{
			ki = k->value[j]<<(32-i);
			ki = ki>>31;
			ki2 = k->value[j]<<(32-(e+i));
			ki2 = ki2>>31;
			for (m = 0; m < j; m++)
			{
				ki = ki*2;
				ki2 = ki2*2;}
				t += ki;
				t2 += ki2;
			}
			if (t != 0)
				ECFpAddProj (&rr, Table1+t, a, b, prime, &rr);
			if (t2 != 0)
				ECFpAddProj (&rr, Table1+length+t2, a, b, prime, &rr);
	}
	if (FP_IsZero(&rr.z))
		result->isInfinite = 1;
	else
	{
		result->isInfinite = 0;
		FP_Invert (&rr.z, prime, &inverse);

		FPSqr_Mul (&inverse, prime, &temp);
		(* FpMul) (&rr.x, &temp, prime, &result->x);
		(* FpMul)(&temp,&inverse,prime,&inverse);
		(* FpMul) (&rr.y, &inverse, prime, &result->y);
	}

	return 0;
}


static int ECFpDoubleProj (EcFpPointProject *operand, MInt *a,MInt *b,
				MInt *prime, EcFpPointProject *result)
{
	MInt t1, t2, t3, t4, t5, temp;

	if (FP_IsZero (&operand->z))
	{
		MI_WordToMInt (0, &result->x);
		MI_WordToMInt (1, &result->y);
		MI_WordToMInt (0, &result->z);
		return 0;
	}
	MI_Move(&operand->x, &t1);
	MI_Move(&operand->y, &t2);
	MI_Move(&operand->z, &t3);

	MI_Move(prime, &temp);
	temp.value[0] = temp.value[0]-3;
	if(MI_Compare(a, &temp) == 0)
	{
		FPSqr_Mul(&t3, prime, &t4);
		FP_Substract(&t1, &t4, prime, &t5);
		FP_Add(&t1, &t4, prime, &t4);
		FP_Mul(&t4, &t5, prime, &t5);
		FP_Add(&t5, &t5, prime, &temp);
		FP_Add(&temp, &t5, prime, &t4);
	}
	else
	{
		MI_Move(a, &t4);
		FPSqr_Mul(&t3, prime, &t5);
		FPSqr_Mul(&t5, prime, &t5);
		FP_Mul(&t4, &t5, prime, &t5);
		FPSqr_Mul(&t1, prime, &t4);
		FP_Add(&t4, &t4, prime, &temp);
		FP_Add(&temp, &t4, prime, &t4);
		FP_Add(&t5, &t4, prime, &t4);
	}
	FP_Mul(&t2, &t3, prime, &t3);
	FP_Add(&t3, &t3, prime, &t3);
	FPSqr_Mul(&t2, prime, &t2);
	FP_Mul(&t1, &t2, prime, &t5);
	FP_Add(&t5, &t5, prime, &temp);
	FP_Add(&temp, &temp, prime, &t5);
	FPSqr_Mul(&t4, prime, &t1);
	FP_Add(&t5, &t5, prime, &temp);
	FP_Substract(&t1, &temp, prime, &t1);
	FPSqr_Mul(&t2, prime, &t2);
	FP_Add(&t2, &t2, prime, &temp);
	FP_Add(&temp, &temp, prime, &t2);
	FP_Move(&t2, &temp);
	FP_Add(&temp, &temp, prime, &t2);
	FP_Substract(&t5, &t1, prime, &t5);
	FP_Mul(&t4, &t5, prime, &t5);
	FP_Substract(&t5, &t2, prime, &t2);

	MI_Move(&t1, &result->x);
	MI_Move(&t2, &result->y);
	MI_Move(&t3, &result->z);

	return 0;
}


int EcFpPointToPoint(EcFpPoint *pt1 , Point *dest)
{
	int i, len;
	if(pt1->isInfinite == 1)
	{
		pt1->x.length = 0;
		pt1->y.length = 0;
	}
	len = pt1->x.length;
	for (i = 0; i < len; i++)
		dest->x[i] = pt1->x.value[i];
	for (i = len; i < PARABUFFER; i++)
		dest->x[i] = 0;
	len = pt1->y.length;
	for(i = 0;i < len; i++)
		dest->y[i] = pt1->y.value[i];
	for(i = len; i<PARABUFFER;i++)
		dest->y[i] = 0;
	return 0;
}


int ECFpKPAddLQs(EcFpPoint *P,EcFpPoint *Q,MInt *u1,MInt *u2,
		 MInt *a, MInt *b,MInt *prime,EcFpPoint *result)
{
	int  i, JSFlong;
	unsigned char JSFKL[258];

	MInt inverse, temp;
	EcFpPoint   Point_PQ[8];
	EcFpPointProject rr;

	JSFlong = JointSFKL_Encode(u1,u2,JSFKL);

	FP_Move (&P->x, &Point_PQ[2].x);
	FP_Move (&P->y, &Point_PQ[2].y);
	FP_Move (&Q->x, &Point_PQ[0].x);
	FP_Move (&Q->y, &Point_PQ[0].y);
	FP_Move (&P->x, &Point_PQ[5].x);
	FpMinus (&P->y, prime, &Point_PQ[5].y);
	FP_Move (&Q->x, &Point_PQ[1].x);
	FpMinus (&Q->y, prime, &Point_PQ[1].y);
	ECFpAdd (P,Q,a,b,prime,&Point_PQ[3]);
	FP_Move (&Point_PQ[3].x, &Point_PQ[7].x);
	FpMinus (&Point_PQ[3].y, prime, &Point_PQ[7].y);

	ECFpAdd (P,&Point_PQ[1],a,b,prime,&Point_PQ[4]);

	FP_Move (&Point_PQ[4].x, &Point_PQ[6].x);
	FpMinus (&Point_PQ[4].y, prime, &Point_PQ[6].y);

	MI_WordToMInt (0, &rr.x);
	MI_WordToMInt (1, &rr.y);
	MI_WordToMInt (0, &rr.z);

	for(i = JSFlong-1; i >= 0; i--){
		ECFpDoubleProj(&rr, a, b, prime, &rr);
		if(JSFKL[i])
			ECFpAddProj(&rr, &Point_PQ[JSFKL[i]-1],
					a, b, prime, &rr);
	 }

	FP_Invert (&rr.z, prime, &inverse);
	FPSqr_Mul (&inverse, prime, &temp);
	FP_Mul (&rr.x, &temp, prime, &result->x);
	FP_Mul(&temp,&inverse,prime,&inverse);
	FP_Mul (&rr.y, &inverse, prime, &result->y);

	return 0;

}


int MI_ModularReduce (MInt *operand, MInt *modulus, MInt *reducedValue)
{
	uint32 ai, t, *cc, *dd;
	uint32 a;
	int i;
	unsigned int ccWords, ddWords, shift;

	MI_RecomputeLength (operand->length,operand);
	MI_RecomputeLength (modulus->length,modulus);

	do {

	if (MI_Compare (operand, modulus) < 0) {
		MI_Move (operand, reducedValue);
	break;
	}

	if ((MI_Move (operand, reducedValue)) != 0)
		break;
	a = modulus->value[modulus->length-1];
	for (i = 0; (i<CMP_WORD_SIZE)&&(a!=0); ++i,a>>=1);

	shift = CMP_WORD_SIZE - i;

	ccWords = reducedValue->length;
	cc = reducedValue->value;
	if ((cc[ccWords] = CMP_ArrayLeftShift (cc, shift, ccWords)) != 0)
		cc[++ ccWords] = 0;

	ddWords = modulus->length;
	dd = modulus->value;
	CMP_ArrayLeftShift (dd, shift, ddWords);
	t = dd[ddWords - 1];

	for (i = ccWords - ddWords; i >= 0; -- i) {
		if (t == MAX_CMP_WORD)
			ai = cc[i + ddWords];
		else
			CMP_WordDiv (&ai, &cc[i + ddWords - 1], t + 1);
		cc[i + ddWords] -= CMP_SubProduct (&cc[i], &cc[i], ai,
					dd, ddWords);

		while (cc[i + ddWords] || (CMP_ArrayCmp (&cc[i], dd,
		ddWords) >= 0)) {
			cc[i + ddWords] -= CMP_ArraySub (&cc[i],
					&cc[i], dd, ddWords);
		}
	}

	CMP_ArrayRightShift (dd, shift, ddWords);
	CMP_ArrayRightShift (cc, shift, ddWords);
	MI_RecomputeLength (ddWords, reducedValue);
	} while (0);

	return 0;
}


int DW_AddProduct (uint32 *a, uint32 *b, uint32 c, uint32 *d,
				unsigned int length)
{
	uint32 carry, t[2];
	unsigned int i;

	carry = 0;
	for (i = 0; i < length; ++ i)
	{
		DWordMult (t, c, d[i]);
		if ((a[i] = b[i] + carry) < carry)
			carry = 1;
		else
			carry = 0;
		if ((a[i] += t[0]) < t[0])
			++ carry;
		carry += t[1];
	}
	return carry;
}


int MI_RecomputeLength (int targetLength, MInt *theInt)
{
	int i;

	for (i = targetLength - 1; i >= 0; -- i)
		if (theInt->value[i] != 0)
			break;
	theInt->length = i + 1;
	return 0;
}


int PriKeyToOctetString(unsigned int *piPrivateKey,int piLenOfPriKey,
				unsigned int OSBuffSize,
				unsigned int *OSLen, unsigned char *DString)
{
	MInt s;
	int i;
	for (i = 0; i < piLenOfPriKey; i++)
		s.value[i] = piPrivateKey[i];
	s.length = piLenOfPriKey;
	MIntToOctetString(&s, OSBuffSize, OSLen, DString);
	return 0;
}


int OctetStringToMInt (const unsigned char *OString, unsigned int OSLen,
					MInt *destInt)
{
	uint32 word;
	int i, j, k, t, words;
	words = (OSLen+MI_BYTES_PER_WORD-1)/MI_BYTES_PER_WORD;
	for (i = OSLen, j = 0; i > 0; i -= 4, ++ j)
	{
		word = 0;
		t = (int)min (i, MI_BYTES_PER_WORD);
		for (k = 0; k < t; ++ k)
		{
			word = (word << MI_BITS_PER_BYTE) | OString[i - t + k];
		}
		destInt->value[j] = word;
	}
	MI_RecomputeLength (words, destInt);

	return 0;
}


int OctetStringToPriKey(const unsigned char *OString, unsigned int OSLen,
				unsigned int *piPrivateKey, int *piLenOfPriKey)
{
	MInt s;
	int i;
	OctetStringToMInt(OString, OSLen, &s);

	for(i = 0;i < s.length; i++)
		piPrivateKey[i] = s.value[i];
	*piLenOfPriKey = s.length;

	return 0;
}


int OctetStringToPubKey(const unsigned char *OString, unsigned int OSLen,
				Point *poPublicKey)
{
	MInt x, y;
	int i;
	unsigned int len;
	len = OSLen/2;
	OctetStringToMInt(OString, len, &x);
	OctetStringToMInt(OString + len, len, &y);

	for(i = 0; i < x.length; i++)
		poPublicKey->x[i] = x.value[i];
	for(i = x.length; i < PARABUFFER; i++)
		poPublicKey->x[i] = 0;
	for(i = 0;i < y.length; i++)
		poPublicKey->y[i] = y.value[i];
	for(i = y.length ; i < PARABUFFER; i++)
		poPublicKey->y[i] = 0;
	return 0;
}



int FP_MulNormal(MInt *multiplicand,MInt *multiplier,
		MInt *p, MInt *product)
{
	uint32 a[MINTLENGTH], *bb, *c;
	int cLen, i, productLen;

	if(FP_IsZero(multiplicand)||FP_IsZero(multiplier))
	{
		product->length =0;
		product->value [0]=0;
		return 0;
	}

	productLen = multiplicand->length + multiplier->length;
	bb = multiplicand->value;    c = multiplier->value;
	cLen = multiplier->length;
	for(i = 0; i < MINTLENGTH; i++)
		a[i] = 0;

	for (i = 0; i < multiplicand->length; ++ i)
		a[cLen + i] += DW_AddProduct (&a[i], &a[i], bb[i], c, cLen);

	for(i = 0; i < productLen; i++)
		product->value[i] = a[i];
	MI_RecomputeLength (productLen , product);
	MI_ModularReduce (product, p, product);

	return 0;
}

int  gettalbe()
{
	MInt t1, t2;
	int i, j;
	for(j = 0;j < 128; j++)
	{
		for(i = 0; i < 6; i++)
		{
			t1.value[i] = pTablexy[j*12+i];
			t1.length = 6;
			t2.value[i] = pTablexy[j*12+6+i];
			t2.length = 6;
			MI_RecomputeLength(6, &t1);
			MI_RecomputeLength(6, &t2);
			MI_Move(&t1, &(pTable1+j)->x);
			MI_Move(&t2, &(pTable1+j)->y);
		}
	}

	return 0;
}


int ECC_Init(void)
{
	unsigned char p192[30]= {0xBD,0xB6,0xF4,0xFE,0x3E,0x8B,0x1D,0x9E,
				0x0D,0xA8,0xC0,0xD4,0x6F,0x4C,0x31,0x8C,
				0xEF,0xE4,0xAF,0xE3,0xB6,0xB8,0x55,0x1F};

	unsigned char a192[30]= {0xBB,0x8E,0x5E,0x8F,0xBC,0x11,0x5E,0x13,
				0x9F,0xE6,0xA8,0x14,0xFE,0x48,0xAA,0xA6,
				0xF0,0xAD,0xA1,0xAA,0x5D,0xF9,0x19,0x85};

	unsigned char b192[30]= {0x18,0x54,0xBE,0xBD,0xC3,0x1B,0x21,0xB7,
				0xAE,0xFC,0x80,0xAB,0x0E,0xCD,0x10,0xD5,
				0xB1,0xB3,0x30,0x8E,0x6D,0xBF,0x11,0xC1};

	unsigned char x192[30]= {0x4A,0xD5,0xF7,0x04,0x8D,0xE7,0x09,0xAD,
				0x51,0x23,0x6D,0xE6,0x5E,0x4D,0x4B,0x48,
				0x2C,0x83,0x6D,0xC6,0xE4,0x10,0x66,0x40};

	unsigned char y192[30]= {0x02,0xBB,0x3A,0x02,0xD4,0xAA,0xAD,0xAC,
				0xAE,0x24,0x81,0x7A,0x4C,0xA3,0xA1,0xB0,
				0x14,0xB5,0x27,0x04,0x32,0xDB,0x27,0xD2};

	unsigned char n192[30]= {0xBD,0xB6,0xF4,0xFE,0x3E,0x8B,0x1D,0x9E,
				0x0D,0xA8,0xC0,0xD4,0x0F,0xC9,0x62,0x19,
				0x5D,0xFA,0xE7,0x6F,0x56,0x56,0x46,0x77};


	OctetStringToMInt(p192, PARABYTELEN, &TheCurve.P);
	OctetStringToMInt(a192, PARABYTELEN, &TheCurve.A);
	OctetStringToMInt(b192, PARABYTELEN, &TheCurve.B);

	OctetStringToMInt(x192, PARABYTELEN, &TheCurve.BasePoint.x);
	OctetStringToMInt(y192, PARABYTELEN, &TheCurve.BasePoint.y);
	OctetStringToMInt(n192, PARABYTELEN, &TheCurve.Order);
	FpMul = FP_MulNormal;

	gettalbe();

	return 1;
}


int Generate_PubKey(unsigned int *piPrivateKey,int piLenOfPriKey,
				 Point *poPublicKey)
{
	int i;
	EcFpPoint point0;
	MInt key;

	for(i=0;i<piLenOfPriKey;i++)
		key.value[i]=piPrivateKey[i];
	key.length=piLenOfPriKey;

	if(MI_Compare(&key,&TheCurve.Order)>=0)
		return 0;

	ECFpKTimes_FixP(&TheCurve.BasePoint,pTable1,&key,
		&TheCurve.A, &TheCurve.B,&TheCurve.P, &point0);
	EcFpPointToPoint(&point0 ,poPublicKey);

	return 1;
}




int Verify_With_Public_Key(const uint8 *pbData, int iDataLen,
			const uint8 *pbSignIn, int iSignInLen, const Point oPubPoint)
{
	int len, status;
	MInt c, u1, u2, s, r, hashValue, temp;
	EcFpPoint  point2, Q;

	len=iSignInLen/2;
	PointToEcFpPoint(&oPubPoint, &Q);
	sha256_digest_int(pbData, iDataLen, &hashValue);
	MI_ModularReduce (&hashValue, &TheCurve.Order, &temp);
	MI_Move(&temp, &hashValue);

	OctetStringToMInt(pbSignIn, len, &r);
	OctetStringToMInt(pbSignIn + len, len, &s);

	FP_Invert(&s, &TheCurve.Order, &c);
	FP_MulNormal (&hashValue, &c,&TheCurve.Order, &u1);
	FP_MulNormal (&r, &c,&TheCurve.Order, &u2);

	ECFpKPAddLQs(&TheCurve.BasePoint, &Q, &u1, &u2, &TheCurve.A,
			     &TheCurve.B, &TheCurve.P, &point2);

	MI_ModularReduce(&point2.x, &TheCurve.Order, &u1);

	if (MI_Compare (&u1, &r) != 0)
		status = 0;
	else
		status = 1;

	return status;
}


static int ECFpAddProj (EcFpPointProject *addend1,EcFpPoint *addend2,
			MInt *a,MInt * b,MInt *prime,EcFpPointProject *result)
{
	MInt t1, t2, t3, t4, t5, t7, temp;

	if (FP_IsZero (&addend1->z))
	{
		FP_Move (&addend2->x, &result->x);
		FP_Move (&addend2->y, &result->y);
		MI_WordToMInt(1,&result->z);
		return 0;
	}

	MI_Move(&addend1->x, &t1);
	MI_Move(&addend1->y, &t2);
	MI_Move(&addend1->z, &t3);
	FPSqr_Mul(&t3, prime, &t7);
	FP_Mul(&addend2->x, &t7, prime,&t4);
	FP_Mul(&t3,&t7, prime, &t7);
	FP_Mul(&addend2->y, &t7, prime, &t5);
	FP_Substract(&t1, &t4, prime, &t4);
	FP_Substract(&t2, &t5, prime, &t5);
	if(FP_IsZero(&t4))
	{
		if(FP_IsZero(&t5)){
			ECFpDoubleProj (addend1, a, b, prime, result);	return 0;
		}
		else{
			MI_WordToMInt (0, &result->x);MI_WordToMInt (1, &result->y);
			MI_WordToMInt (0, &result->z);		return 0;
		}
	}
	FP_Add(&t1, &t1, prime, &temp);
	FP_Substract(&temp, &t4, prime, &t1);
	FP_Add(&t2, &t2, prime, &temp);
	FP_Substract(&temp, &t5, prime, &t2);
	FP_Mul(&t3, &t4, prime, &t3);
	FPSqr_Mul(&t4, prime, &t7);
	FP_Mul(&t4, &t7, prime, &t4);
	FP_Mul(&t1, &t7, prime, &t7);
	FPSqr_Mul(&t5, prime, &t1);
	FP_Substract(&t1, &t7, prime, &t1);
	FP_Add(&t1, &t1, prime, &temp);
	FP_Substract(&t7, &temp, prime, &t7);
	FP_Mul(&t5, &t7, prime, &t5);
	FP_Mul(&t2, &t4, prime, &t4);
	FP_Substract(&t5, &t4, prime, &result->y);
	FpDivByTwo(&result->y,prime);
	MI_Move(&t1, &result->x);
	MI_Move(&t3, &result->z);

	return 0;
}

int Sign_With_Private_Key(uint8 *pbSignOut, const uint8 *pbData, int iLenIn,
		const unsigned int *piPrivateKey, int iLenOfPriKey)
{
	int i;
	MInt  k, t, r;
	MInt  t1, s0;
	EcFpPoint point0;
	MInt priKey,hashValue, temp;
	unsigned int signLen, len;

	priKey.length = iLenOfPriKey;
	for (i = 0; i < iLenOfPriKey; i++)
		priKey.value[i] = piPrivateKey[i];
	sha256_digest_int(pbData, iLenIn, &hashValue);
	MI_ModularReduce (&hashValue, &TheCurve.Order, &temp);
	MI_Move(&temp, &hashValue);

	do{
		do {
			GenRandomNumber(&k,&TheCurve.Order);
			ECFpKTimes_FixP(&TheCurve.BasePoint,pTable1,
				&k,&TheCurve.A,&TheCurve.B,&TheCurve.P,&point0) ;
			MI_ModularReduce (&point0.x,&TheCurve.Order, &r);
		}while (FP_IsZero(&r));

		FP_MulNormal(&priKey, &r,&TheCurve.Order, &t);
		FP_Add (&t, &hashValue, &TheCurve.Order, &t1);
		FP_Invert (&k,&TheCurve.Order, &t);
		FP_MulNormal (&t, &t1, &TheCurve.Order, &s0);
	}while (FP_IsZero(&s0));

	signLen = TheCurve.P.length*4;

	MIntToFixedLenOS(&r, signLen, 100, &len, pbSignOut);
	MIntToFixedLenOS(&s0, signLen, 100, &len, pbSignOut + signLen);
	signLen = signLen*2;

	return signLen;
}

long asue_random(long s)
{
	int SeedArray[0x38];
	int num2 = 0x9a4ec86 - s;
	int num3 = 1;
	int index;
	int inextp;
	int num;
	int i,j,k;

	SeedArray[0x37] = num2;

	for (i = 1; i < 0x37; i++)
	{
		index = (0x15 * i) % 0x37;
		SeedArray[index] = num3;
		num3 = num2 - num3;
		if (num3 < 0)
		{
			num3 += 0x7fffffff;
		}
		num2 = SeedArray[index];
	}
	for (j = 1; j < 5; j++)
	{
		for (k = 1; k < 0x38; k++)
		{
			SeedArray[k] -= SeedArray[1 + ((k + 30) % 0x37)];
			if (SeedArray[k] < 0)
			{
				SeedArray[k] += 0x7fffffff;
			}
		}
	}
	index = 0;
	inextp = 0x15;
	if (++index >= 0x38)
	{
	    index = 1;
	}
	if (++inextp >= 0x38)
	{
	    inextp = 1;
	}
	num = SeedArray[index] - SeedArray[inextp];
	if (num < 0)
	{
	    num += 0x7fffffff;
	}
	SeedArray[index] = num;
	return (long)num;
}


int KTimesPoint(unsigned int *piPrivateKey,int *piLenOfPriKey,
		Point *poTempPublicKey,const int iKeyBitLen1,Point *poAddPoint,
		const int iKeyBitLen2)
{

	int i;
	EcFpPoint point0;
	EcFpPoint point1;
	MInt key;


	PointToEcFpPoint(poTempPublicKey,&point1);
	for ( i = 0; i<*piLenOfPriKey; i++)
		key.value[i] = piPrivateKey[i];
	key.length=*piLenOfPriKey;

	if (MI_Compare(&key,&TheCurve.Order)>=0)
		return 0;

	ECFpKTimes(&point1, &key, &TheCurve.A, &TheCurve.B,
				&TheCurve.P, &point0);
	EcFpPointToPoint(&point0 , poAddPoint);

	return 1;


}
