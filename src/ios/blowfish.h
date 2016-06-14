// blowfish.h     interface file for blowfish.cpp
// _THE BLOWFISH ENCRYPTION ALGORITHM_
// by Bruce Schneier
// Revised code--3/20/94
// Converted to C++ class 5/96, Jim Conger
// Fixed byte ordering issues for use between big endian/little endian platforms 8/2008, Paul Fossey 
//
#ifndef _BLOWFISH_H
#define _BLOWFISH_H

#define MAXKEYBYTES 	56		// 448 bits max
#define NPASS           16		// SBox passes

#define DWORD  		unsigned long
#define WORD  		unsigned short
#define BYTE  		unsigned char

#define BLOWFISH_BLOCKSIZE 8

class CBlowFish
{
        /**
	 * The m_key array and it's associated m_nKeySize data are set by the SetKey() method.<br>
	 * The Initialize() method uses m_key and m_nKeySize to create the cipher key if the m_bSetKey member is 1.
	 */
	BYTE		m_key[256];
	BYTE		m_nKeySize;

	/** The m_fSetKey flag is set to 0 by the ctor.<br>
	 * The SetKey() method sets m_fSetKey to 1 if a non-nul key parameter is specified.<br>
	 * The Initialize() method uses the m_key and m_nKeySize member data as the cipher key if m_bSetKey is 1.
	 */
	BYTE		m_bSetKey;

private:
	DWORD 		* PArray ;
	DWORD		(* SBoxes)[256];
	
	/** Returns the low order byte from the specified word.
	 *  NOTE: This means bits 0..7 (0xFF) without regard to local endian ordering.
         */
	unsigned char   LowByte(unsigned int ui);

	/** The byte2blk method moves 4 bytes into xl and 4 bytes into xr.
	 *  px[ABCDEFGH] ==> xl[ABCD] , xr[EFGH] 
         */
	void            byte2blk (BYTE *px, DWORD &xl, DWORD &xr );

	/** The blk2byte method moves 4 bytes from xl and 4 bytes from xr into px.
	 * xl[ABCD] , xr[EFGH] ==> px[ABCDEFGH]
	 */
	void            blk2byte (DWORD &xl, DWORD &xr, BYTE *px);

	/** Calls byte2blk, Blowfish_encipher(xl,xr), blk2byte */
	void 		Blowfish_encipher ( BYTE *px ) ;

	/** Calls byte2blk, Blowfish_encipher(xl,xr), blk2byte */
	void 		Blowfish_decipher ( BYTE *px ) ;

	void 		Blowfish_encipher (DWORD *xl, DWORD *xr) ;
	void 		Blowfish_decipher (DWORD *xl, DWORD *xr) ;

public:
	CBlowFish () ;
	~CBlowFish() ;

	/**
	 * Set the m_key and m_nKeySize members from the specified aKey parameter.<br>
	 * The aKey parameter is specified as a hex encoded string that is delimited by '-' characters.<br>
	 * This method parses the aKey string and places it's binary value into the m_key array.
	 *
	 * @param aKey Ptr. to a nul terminated string representation of the cipher key.
	 * @return none.
	 */
	void		SetKey(const char * aKey);

	/**
	 * Initilaize blowfish for use.<br>
	 * If a previous call to SetKey passed in a non-nul key string, then the key and keybytes parameter is ignored.
	 * @param key Ptr. to the desired key bytes.
	 * @param keybytes The number of bytes contained in the key array.
	 * @return none.
	 */
	void 		Initialize (const BYTE key[], int keybytes) ;

	DWORD		GetOutputLength (DWORD lInputLong) ;

	DWORD		Encode (BYTE * pInput, BYTE * pOutput, DWORD lSize) ;

	void		Decode (BYTE * pInput, BYTE * pOutput, DWORD lSize) ;
} ;

// choose a byte order for your hardware

#if defined(MACOSX)

#if (defined (__i386__) || defined( __x86_64__ ))

#define ORDER_DCBA

#else

#define ORDER_ABCD

#endif

#else

#define ORDER_DCBA

#endif

#ifdef ORDER_DCBA  	// DCBA - little endian - intel
	union aword {
	  DWORD dword;
	  BYTE byte [4];
	  struct {
	    unsigned int byte3:8;
	    unsigned int byte2:8;
	    unsigned int byte1:8;
	    unsigned int byte0:8;
	  } w;
	};
#endif

#ifdef ORDER_ABCD  	// ABCD - big endian - motorola
	union aword {
	  DWORD dword;
	  BYTE byte [4];
	  struct {
	    unsigned int byte0:8;
	    unsigned int byte1:8;
	    unsigned int byte2:8;
	    unsigned int byte3:8;
	  } w;
	};
#endif

#ifdef ORDER_BADC  	// BADC - vax
	union aword {
	  DWORD dword;
	  BYTE byte [4];
	  struct {
	    unsigned int byte1:8;
	    unsigned int byte0:8;
	    unsigned int byte3:8;
	    unsigned int byte2:8;
	  } w;
};
#endif

extern unsigned char BLOWFISH_KEY[16];

//Extract low order byte
inline unsigned char CBlowFish::LowByte(unsigned int ui)
{
	return (unsigned char)(ui & 0xff);
}

#endif

