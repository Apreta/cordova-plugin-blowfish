// blowfish.cpp   C++ class implementation of the BLOWFISH encryption algorithm
// _THE BLOWFISH ENCRYPTION ALGORITHM_
// by Bruce Schneier
// Revised code--3/20/94
// Converted to C++ class 5/96, Jim Conger
// Added IIC/ICECore/Conferencing mods, unknown
// Fixed byte ordering issues for use between big endian/little endian platforms 8/2008, Paul Fossey 

#include "blowfish.h"
#include "blowfish.h2"	// holds the random digit tables
#include <string.h>

#define S(x,i) (SBoxes[i][x.w.byte##i])
#define bf_F(x) (((S(x,0) + S(x,1)) ^ S(x,2)) + S(x,3))
#define ROUND(a,b,n) (a.dword ^= bf_F(b) ^ PArray[n])


unsigned char BLOWFISH_KEY[16] = {0x3E,0x4B,0x49,0x45,0xC5,0x3F,0x40,0x46,0x8C,0x27,0x02,0x01,0xB6,0xCC,0x26,0xDA};		// 128-bit GUID

CBlowFish::CBlowFish ()
{
 	PArray = new DWORD [18] ;
 	SBoxes = new DWORD [4][256] ;

	// IIC
	m_key[0] = 0;
	m_nKeySize = 0;
	m_bSetKey = 0;
}

CBlowFish::~CBlowFish ()
{
	delete PArray ;
	delete [] SBoxes ;
}

void CBlowFish::SetKey(const char * aKey)	// IIC
{
	DWORD i, len = strlen(aKey);
	BYTE n;
	if (aKey && strlen(aKey)>0)
	{
		m_nKeySize = 0;
		for (i=0; i<len; )
		{
			if (aKey[i]=='-')
			{
				i++; continue;
			}
			if (aKey[i] >= 'a')
			{
				n = aKey[i] - 'a' + 10;
			}
			else if (aKey[i] >= 'A')
			{
				n = aKey[i] - 'A' + 10;
			}
			else
				n = aKey[i] - '0';

			i++;
			n = n << 4;

			if (aKey[i] >= 'a')
			{
				n += aKey[i] - 'a' + 10;
			}
			else if (aKey[i] >= 'A')
			{
				n += aKey[i] - 'A' + 10;
			}
			else
				n += aKey[i] - '0';

			i++;
			m_key[m_nKeySize++] = n;
		}

		m_bSetKey = 1;
	}
}

void CBlowFish::byte2blk (BYTE *px, DWORD &xl, DWORD &xr )
{
#if 1 //def LINUX
	xl = *(DWORD*)px;
	xr = *(DWORD*)(px+4);
#else
	unsigned int y;
	BYTE *p = px;

	//Left
	xl = 0;
	y = *p++;
	y <<= 24;
	xl |= y;
	y = *p++;
	y <<= 16;
	xl |= y;
	y = *p++;
	y <<= 8;
	xl |= y;
	y = *p++;
	xl |= y;

	//Right
	xr = 0;
	y = *p++;
	y <<= 24;
	xr |= y;
	y = *p++;
	y <<= 16;
	xr |= y;
	y = *p++;
	y <<= 8;
	xr |= y;
	y = *p++;
	xr |= y;
#endif
}

void CBlowFish::blk2byte (DWORD &xl, DWORD &xr, BYTE *px)
{
#if 1 //def LINUX
	*(DWORD*)px = xl;
	*(DWORD*)(px+4) = xr;
#else
	unsigned int y;

	BYTE *p = px + 8;

	//Right
	y = xr;
	*--p = LowByte(y);
	y = xr >> 8;
	*--p = LowByte(y);
	y = xr >> 16;
	*--p = LowByte(y);
	y = xr >> 24;
	*--p = LowByte(y);
	//Left
	y = xl;
	*--p = LowByte(y);
	y = xl >> 8;
	*--p = LowByte(y);
	y = xl >> 16;
	*--p = LowByte(y);
	y = xl >> 24;
	*--p = LowByte(y);
#endif
}

void CBlowFish::Blowfish_encipher (BYTE *px)
{
    DWORD xl, xr;

    byte2blk( px, xl, xr );

    Blowfish_encipher( &xl, &xr );

    blk2byte( xl, xr, px );
}

void CBlowFish::Blowfish_decipher (BYTE *px)
{
    DWORD xl,xr;

    byte2blk( px, xl, xr );

    Blowfish_decipher( &xl, &xr );

    blk2byte( xl, xr, px );
}
	// the low level (private) encryption function
void CBlowFish::Blowfish_encipher (DWORD *xl, DWORD *xr)
{
	union aword  Xl, Xr ;

	Xl.dword = *xl ;
	Xr.dword = *xr ;

	Xl.dword ^= PArray [0];
	ROUND (Xr, Xl, 1) ;  ROUND (Xl, Xr, 2) ;
	ROUND (Xr, Xl, 3) ;  ROUND (Xl, Xr, 4) ;
	ROUND (Xr, Xl, 5) ;  ROUND (Xl, Xr, 6) ;
	ROUND (Xr, Xl, 7) ;  ROUND (Xl, Xr, 8) ;
	ROUND (Xr, Xl, 9) ;  ROUND (Xl, Xr, 10) ;
	ROUND (Xr, Xl, 11) ; ROUND (Xl, Xr, 12) ;
	ROUND (Xr, Xl, 13) ; ROUND (Xl, Xr, 14) ;
	ROUND (Xr, Xl, 15) ; ROUND (Xl, Xr, 16) ;
	Xr.dword ^= PArray [17] ;

	*xr = Xl.dword ;
	*xl = Xr.dword ;
}

	// the low level (private) decryption function
void CBlowFish::Blowfish_decipher (DWORD *xl, DWORD *xr)
{
   union aword  Xl ;
   union aword  Xr ;

   Xl.dword = *xl ;
   Xr.dword = *xr ;

   Xl.dword ^= PArray [17] ;
   ROUND (Xr, Xl, 16) ;  ROUND (Xl, Xr, 15) ;
   ROUND (Xr, Xl, 14) ;  ROUND (Xl, Xr, 13) ;
   ROUND (Xr, Xl, 12) ;  ROUND (Xl, Xr, 11) ;
   ROUND (Xr, Xl, 10) ;  ROUND (Xl, Xr, 9) ;
   ROUND (Xr, Xl, 8) ;   ROUND (Xl, Xr, 7) ;
   ROUND (Xr, Xl, 6) ;   ROUND (Xl, Xr, 5) ;
   ROUND (Xr, Xl, 4) ;   ROUND (Xl, Xr, 3) ;
   ROUND (Xr, Xl, 2) ;   ROUND (Xl, Xr, 1) ;
   Xr.dword ^= PArray[0];

   *xl = Xr.dword;
   *xr = Xl.dword;
}


// constructs the enctryption sieve
void CBlowFish::Initialize (const BYTE _key[], int _keybytes)
{
	int  		i, j ;
	DWORD  		data, datal, datar ;
	union aword temp ;
	const BYTE * key = _key;	// IIC
	int	 keybytes = _keybytes;	// IIC

	if (m_bSetKey)	// IIC
	{
		key = m_key;
		keybytes = m_nKeySize;
	}

	// first fill arrays from data tables
	for (i = 0 ; i < 18 ; i++)
		PArray [i] = bf_P [i] ;

	for (i = 0 ; i < 4 ; i++)
	{
	 	for (j = 0 ; j < 256 ; j++)
	 		SBoxes [i][j] = bf_S [i][j] ;
	}

	j = 0 ;
	for (i = 0 ; i < NPASS + 2 ; ++i)
	{
		temp.dword = 0 ;
		temp.w.byte0 = key[j];
		temp.w.byte1 = key[(j+1) % keybytes] ;
		temp.w.byte2 = key[(j+2) % keybytes] ;
		temp.w.byte3 = key[(j+3) % keybytes] ;
		data = temp.dword ;
		PArray [i] ^= data ;
		j = (j + 4) % keybytes ;
	}

	datal = 0 ;
	datar = 0 ;

	for (i = 0 ; i < NPASS + 2 ; i += 2)
	{
		Blowfish_encipher (&datal, &datar) ;
		PArray [i] = datal ;
		PArray [i + 1] = datar ;
	}

	for (i = 0 ; i < 4 ; ++i)
	{
		for (j = 0 ; j < 256 ; j += 2)
		{
		  Blowfish_encipher (&datal, &datar) ;
		  SBoxes [i][j] = datal ;
		  SBoxes [i][j + 1] = datar ;
		}
	}
}

// get output length, which must be even MOD 8
DWORD CBlowFish::GetOutputLength (DWORD lInputLong)
{
	DWORD 	lVal ;

	lVal = lInputLong % 8 ;	// find out if uneven number of bytes at the end
	if (lVal != 0)
		return lInputLong - lVal ;	// IIC
	else
		return lInputLong ;
}

// Encode pIntput into pOutput.  Input length in lSize.  Returned value
// is length of output which will be even MOD 8 bytes.  Input buffer and
// output buffer can be the same, but be sure buffer length is even MOD8.
DWORD CBlowFish::Encode (BYTE * pInput, BYTE * pOutput, DWORD lSize)
{
	DWORD 	lCount, lOutSize, lGoodBytes ;
	BYTE	*pi, *po ;
	int		i, j ;
	int		SameDest = (pInput == pOutput ? 1 : 0) ;

	lOutSize = GetOutputLength (lSize) ;
	for (lCount = 0 ; lCount < lOutSize ; lCount += 8)
	{
		if (SameDest)	// if encoded data is being written into input buffer
		{
		 	if (lCount < lSize - 7)	// if not dealing with uneven bytes at end
		 	{
		 	 	Blowfish_encipher ( pInput ) ;
		 	}
		 	else		// pad end of data with null bytes to complete encryption
		 	{
				po = pInput + lSize ;	// point at byte past the end of actual data
				j = (int) (lOutSize - lSize) ;	// number of bytes to set to null
				for (i = 0 ; i < j ; i++)
					*po++ = 0 ;
		 	 	Blowfish_encipher ( pInput ) ;
		 	}
		 	pInput += 8 ;
		}
		else 			// output buffer not equal to input buffer, so must copy
		{               // input to output buffer prior to encrypting
		 	if (lCount < lSize - 7)	// if not dealing with uneven bytes at end
		 	{
		 		pi = pInput ;
		 		po = pOutput ;
		 		for (i = 0 ; i < 8 ; i++)
// copy bytes to output
		 			*po++ = *pi++ ;
		 	 	Blowfish_encipher ( pOutput ) ;
		 	}
		 	else		// pad end of data with null bytes to complete encryption
		 	{
		 		lGoodBytes = lSize - lCount ;	// number of remaining data bytes
		 		po = pOutput ;
		 		for (i = 0 ; i < (int) lGoodBytes ; i++)
		 			*po++ = *pInput++ ;
		 		for (j = i ; j < 8 ; j++)
		 			*po++ = 0 ;
		 	 	Blowfish_encipher ( pOutput ) ;
		 	}
		 	pInput += 8 ;
		 	pOutput += 8 ;
		}
	}

	for (lCount = lOutSize ; lCount < lSize ; lCount ++) {	// IIC
		*pOutput++ = *pInput++;
	}

	return lOutSize ;
 }

	// Decode pIntput into pOutput.  Input length in lSize.  Input buffer and
	// output buffer can be the same, but be sure buffer length is even MOD8.
void CBlowFish::Decode (BYTE * pInput, BYTE * pOutput, DWORD lSize)
{
	DWORD 	lCount, lOutSize ;
	BYTE	*pi, *po ;
	int		i ;
	int		SameDest = (pInput == pOutput ? 1 : 0) ;

	lOutSize = GetOutputLength (lSize) ;
	for (lCount = 0 ; lCount < lOutSize ; lCount += 8)
	{
		if (SameDest)	// if encoded data is being written into input buffer
		{
	 	 	Blowfish_decipher ( pInput ) ;
		 	pInput += 8 ;
		}
		else 			// output buffer not equal to input buffer
		{               // so copy input to output before decoding
	 		pi = pInput ;
	 		po = pOutput ;
	 		for (i = 0 ; i < 8 ; i++)
	 			*po++ = *pi++ ;
	 	 	Blowfish_decipher ( pOutput ) ;
		 	pInput += 8 ;
		 	pOutput += 8 ;
		}
	}

	for (lCount = lOutSize ; lCount < lSize ; lCount ++) {	// IIC
		*pOutput++ = *pInput++;
	}
}
