/*******************************************************************************
* Constant-time implementation of the GIFT-64 block cipher.
*
* See "Fixslicing: A New GIFT Representation" paper available at 
* https://eprint.iacr.org/2020/412.pdf for more details on the fixsliced 
* representation.
* 
* @author	Alexandre Adomnicai, Nanyang Technological University,
*			alexandre.adomnicai@ntu.edu.sg
*
* @date		March 2020
*******************************************************************************/
#include "encrypt.h"
#include "endian.h"
#include "gift64.h"
#include "key_schedule.h"

/****************************************************************************
* The round constants according to the fixsliced representation.
****************************************************************************/
const u32 rconst[28] = {
	0x22000011, 0x00002299, 0x11118811, 0x880000ff,
	0x33111199, 0x990022ee, 0x22119933, 0x880033bb,
	0x22119999, 0x880022ff, 0x11119922, 0x880033cc,
	0x33008899, 0x99002299, 0x33118811, 0x880000ee,
	0x33110099, 0x990022aa, 0x22118833, 0x880022bb,
	0x22111188, 0x88002266, 0x00009922, 0x88003300,
	0x22008811, 0x00002288, 0x00118811, 0x880000bb
};

/****************************************************************************
* Rearranges the key to match the GIFT-64 fixsliced representation.
****************************************************************************/
void rearrange_key(u32* rkey, const u8* key) {
	u32 tmp;
	// key words W6 and W7
	rkey[0] = REARRANGE_KEYWORD_0_1(key[14], key[15]);
	rkey[1] = REARRANGE_KEYWORD_0_1(key[12], key[13]);
	TRANSPOSE_U32(rkey[0]);
	TRANSPOSE_U32(rkey[1]);
	rkey[0] |= 	(rkey[0] << 4); // each key word is interleaved with itself
	rkey[1] |= 	(rkey[1] << 4);
	rkey[0] ^= 0xffffffff; // to save 1 operation in sbox computations
	// key words W4 and W5
	rkey[2] = REARRANGE_KEYWORD_0_1(key[10], key[11]);
	rkey[3] = REARRANGE_KEYWORD_0_1(key[8], key[9]);
	rkey[2] |= (rkey[2] << 4);
	rkey[3] |= (rkey[3] << 4);
	rkey[2] ^= 0xffffffff;
	SWAPMOVE(rkey[2], rkey[2], 0x22222222, 2);
	SWAPMOVE(rkey[3], rkey[3], 0x22222222, 2);
	// key words W2 and W3
	rkey[4] = REARRANGE_KEYWORD_2_3(key[6], key[7]);
	rkey[5] = REARRANGE_KEYWORD_2_3(key[4], key[5]);
	TRANSPOSE_U32(rkey[4]);
	TRANSPOSE_U32(rkey[5]);
	SWAPMOVE(rkey[4], rkey[4], 0x00000f00, 16);
	SWAPMOVE(rkey[5], rkey[5], 0x00000f00, 16);
	rkey[4] |= (rkey[4] << 4);
	rkey[5] |= (rkey[5] << 4);
	rkey[4] ^= 0xffffffff;
	// key words W0 and W1
	rkey[6] = REARRANGE_KEYWORD_2_3(key[2], key[3]);
	rkey[7] = REARRANGE_KEYWORD_2_3(key[0], key[1]);
	rkey[6] |= (rkey[6] << 4);
	rkey[7] |= (rkey[7] << 4);
	rkey[6] ^= 0xffffffff;
}

/****************************************************************************
* Rearranges the keys 'key0' and 'key1' to match the GIFT-64 fixsliced 
* representation. Same as 'rearrange_key' but with 2 different keys so that 
* crypto primitives based on GIFT-64 that need to encrypt several blocks with
* different keys (e.g. LOTUS) can take advantage of fixslicing.
****************************************************************************/
void rearrange_2_keys(u32* rkey, const u8* key0, const u8* key1) {
	u32 tmp;
	// key words W6 and W7
	rkey[0] = REARRANGE_KEYWORD_0_1(key0[14], key0[15]);
	tmp = REARRANGE_KEYWORD_0_1(key1[14], key1[15]);
	rkey[0] |= 	(tmp << 4); 	// interleave (nibble-wise) the 2 key words
	rkey[1] = REARRANGE_KEYWORD_0_1(key0[12], key0[13]);
	tmp = REARRANGE_KEYWORD_0_1(key1[12], key1[13]);
	rkey[1] |= 	(tmp << 4);		// interleave (nibble-wise) the 2 key words
	TRANSPOSE_U32(rkey[0]);
	TRANSPOSE_U32(rkey[1]);
	rkey[0] ^= 0xffffffff; 		// to save 1 operation in sbox computations
	// key words W4 and W5
	rkey[2] = REARRANGE_KEYWORD_0_1(key0[10], key0[11]);
	tmp = REARRANGE_KEYWORD_0_1(key1[10], key1[11]);
	rkey[2] |= 	(tmp << 4);
	rkey[3] = REARRANGE_KEYWORD_0_1(key0[8], key0[9]);
	tmp = REARRANGE_KEYWORD_0_1(key1[8], key1[9]);
	rkey[3] |= 	(tmp << 4);
	rkey[2] ^= 0xffffffff;
	SWAPMOVE(rkey[2], rkey[2], 0x22222222, 2);
	SWAPMOVE(rkey[3], rkey[3], 0x22222222, 2);
	// key words W2 and W3
	rkey[4] = REARRANGE_KEYWORD_2_3(key0[6], key0[7]);
	tmp = REARRANGE_KEYWORD_2_3(key1[6], key1[7]);
	rkey[4] |= 	(tmp << 4);
	rkey[5] = REARRANGE_KEYWORD_2_3(key0[4], key0[5]);
	tmp = REARRANGE_KEYWORD_2_3(key1[4], key1[5]);
	rkey[5] |= 	(tmp << 4);
	TRANSPOSE_U32(rkey[4]);
	TRANSPOSE_U32(rkey[5]);
	SWAPMOVE(rkey[4], rkey[4], 0x0000ff00, 16);
	SWAPMOVE(rkey[5], rkey[5], 0x0000ff00, 16);
	rkey[4] ^= 0xffffffff;
	// key words W0 and W1
	rkey[6] = REARRANGE_KEYWORD_2_3(key0[2], key0[3]);
	tmp = REARRANGE_KEYWORD_2_3(key1[2], key1[3]);
	rkey[6] |= 	(tmp << 4);
	rkey[7] = REARRANGE_KEYWORD_2_3(key0[0], key0[1]);
	tmp = REARRANGE_KEYWORD_2_3(key1[0], key1[1]);
	rkey[7] |= 	(tmp << 4);
	rkey[6] ^= 0xffffffff;
}

/****************************************************************************
* Updates the rkeys according to the fixsliced representation.
****************************************************************************/
void key_update(u32* next_rkey, const u32* prev_rkey) {
	u32 tmp;
	// 1st round key
	next_rkey[0] = NIBBLE_ROR_1(prev_rkey[0]);
	next_rkey[1] = NIBBLE_ROR_3(prev_rkey[1]) & 0x0000ffff;
	next_rkey[1] |= prev_rkey[1] & 0xffff0000;
	next_rkey[1] = ROR(next_rkey[1], 16);
	// 2nd round key
	next_rkey[2] = ROR(prev_rkey[2], 8);
	tmp = NIBBLE_ROR_2(prev_rkey[3]);
	next_rkey[3] = tmp & 0x99999999;
	next_rkey[3] |= ROR(tmp & 0x66666666, 24);
	// 3rd round key
	next_rkey[4] = NIBBLE_ROR_3(prev_rkey[4]);
	tmp = ROR(prev_rkey[5], 16);
	next_rkey[5] = NIBBLE_ROR_1(tmp) & 0x00ffff00;
	next_rkey[5] |= tmp & 0xff0000ff;
	// 4th round key
	next_rkey[6] = ROR(prev_rkey[6], 24);
	tmp = NIBBLE_ROR_2(prev_rkey[7]);
	next_rkey[7] = tmp & 0x33333333;
	next_rkey[7] |= ROR(tmp & 0xcccccccc, 8);
}

/****************************************************************************
* Precomputes all round keys for a given encryption key.
****************************************************************************/
void precompute_rkeys(u32* rkey, const u8* key) {
	rearrange_key(rkey, key);
	for(int i = 0; i < 48; i += 8)
		key_update(rkey + i + 8, rkey + i);
}

/****************************************************************************
* Precomputes all round keys. Same as 'precompute_rkeys' but with 2 different
* keys so that crypto primitives based on GIFT-64 that need to encrypt
* several blocks with different keys (e.g. LOTUS) can take advantage of
* fixslicing.
****************************************************************************/
void precompute_2_rkeys(u32* rkey, const u8* key0, const u8* key1) {
	rearrange_2_keys(rkey, key0, key1);
	for(int i = 0; i < 48; i += 8)
		key_update(rkey + i + 8, rkey + i);
}

/****************************************************************************
* Fills the internal state with two 64-bit blocks using a nibble-interleaved 
* row-wise bitsliced representation.
****************************************************************************/
void packing(u32* state, const u8* block0, const u8* block1) {
	u32 tmp;
	state[0] = U32BIG(*(u32*)(block0 + 4));
	state[1] = U32BIG(*(u32*)(block1 + 4));
	state[2] = U32BIG(*(u32*)block0);
	state[3] = U32BIG(*(u32*)block1);
    SWAPMOVE(state[0], state[0], 0x0a0a0a0a, 3);
    SWAPMOVE(state[0], state[0], 0x00cc00cc, 6);
    SWAPMOVE(state[0], state[0], 0x0000ff00, 8);
    SWAPMOVE(state[1], state[1], 0x0a0a0a0a, 3);
    SWAPMOVE(state[1], state[1], 0x00cc00cc, 6);
    SWAPMOVE(state[1], state[1], 0x0000ff00, 8);
    SWAPMOVE(state[2], state[2], 0x0a0a0a0a, 3);
    SWAPMOVE(state[2], state[2], 0x00cc00cc, 6);
    SWAPMOVE(state[2], state[2], 0x0000ff00, 8);
    SWAPMOVE(state[3], state[3], 0x00cc00cc, 6);
    SWAPMOVE(state[3], state[3], 0x0a0a0a0a, 3);
    SWAPMOVE(state[3], state[3], 0x0000ff00, 8);
	SWAPMOVE(state[0], state[1], 0x0f0f0f0f, 4);
    SWAPMOVE(state[2], state[3], 0x0f0f0f0f, 4);
    SWAPMOVE(state[0], state[2], 0x0000ffff, 16);
    SWAPMOVE(state[1], state[3], 0x0000ffff, 16);
}

/****************************************************************************
* Fills the output from the internal state.
****************************************************************************/
void unpacking(u8* block0, u8* block1, u32* state) {
	u32 tmp;
    SWAPMOVE(state[0], state[2], 0x0000ffff, 16);
    SWAPMOVE(state[1], state[3], 0x0000ffff, 16);
	SWAPMOVE(state[0], state[1], 0x0f0f0f0f, 4);
    SWAPMOVE(state[2], state[3], 0x0f0f0f0f, 4);
    SWAPMOVE(state[0], state[0], 0x0000ff00, 8);
    SWAPMOVE(state[1], state[1], 0x0000ff00, 8);
    SWAPMOVE(state[2], state[2], 0x0000ff00, 8);
    SWAPMOVE(state[3], state[3], 0x0000ff00, 8);
    SWAPMOVE(state[0], state[0], 0x00cc00cc, 6);
    SWAPMOVE(state[1], state[1], 0x00cc00cc, 6);
    SWAPMOVE(state[2], state[2], 0x00cc00cc, 6);
    SWAPMOVE(state[3], state[3], 0x00cc00cc, 6);
    SWAPMOVE(state[0], state[0], 0x0a0a0a0a, 3);
    SWAPMOVE(state[1], state[1], 0x0a0a0a0a, 3);
    SWAPMOVE(state[2], state[2], 0x0a0a0a0a, 3);
    SWAPMOVE(state[3], state[3], 0x0a0a0a0a, 3);
    U8BIG(block0 + 4, state[0]);
    U8BIG(block1 + 4, state[1]);
    U8BIG(block0, state[2]);
    U8BIG(block1, state[3]);
}

/****************************************************************************
* Fills the internal state with two 64-bit blocks. As the input is expected 
* to be in a row-wise bitsliced representation, it only consists in 
* interleaving the nibbles.
****************************************************************************/
void packing_interleave(u32* state, const u8* block0, const u8* block1) {
	u32 tmp;
	state[0] = U32BIG(*(u32*)(block0 + 4));
	state[1] = U32BIG(*(u32*)(block1 + 4));
	state[2] = U32BIG(*(u32*)block0);
	state[3] = U32BIG(*(u32*)block1);
	SWAPMOVE(state[0], state[1], 0x00000f0f, 4);
	SWAPMOVE(state[2], state[3], 0x00000f0f, 4);
	SWAPMOVE(state[0], state[1], 0x0000ffff, 16);
	SWAPMOVE(state[2], state[3], 0x0000ffff, 16);
	SWAPMOVE(state[0], state[0], 0x0000ff00, 8);
	SWAPMOVE(state[1], state[1], 0x0000ff00, 8);
	SWAPMOVE(state[2], state[2], 0x0000ff00, 8);
	SWAPMOVE(state[3], state[3], 0x0000ff00, 8);
}

/****************************************************************************
* Fills the output from the internal state, in a row-wise bitsliced manner.
****************************************************************************/
void unpacking_interleave(u8* block0, u8* block1, u32* state) {
	u32 tmp;
	SWAPMOVE(state[0], state[0], 0x0000ff00, 8);
	SWAPMOVE(state[1], state[1], 0x0000ff00, 8);
	SWAPMOVE(state[2], state[2], 0x0000ff00, 8);
	SWAPMOVE(state[3], state[3], 0x0000ff00, 8);
	SWAPMOVE(state[0], state[1], 0x0000ffff, 16);
	SWAPMOVE(state[2], state[3], 0x0000ffff, 16);
	SWAPMOVE(state[0], state[1], 0x00000f0f, 4);
	SWAPMOVE(state[2], state[3], 0x00000f0f, 4);
    U8BIG(block0 + 4, state[0]);
    U8BIG(block1 + 4, state[1]);
    U8BIG(block0, state[2]);
    U8BIG(block1, state[3]);
}

/****************************************************************************
* Encryption of 64-bit blocks. Note that 'ptext_len' must be a mutliple of 8.
****************************************************************************/
int gift64_encrypt_ecb(u8* ctext, const u8* ptext, u32 ptext_len, const u8* key) {
	u32 state[4], rkey[56];
	precompute_rkeys(rkey, key);
	while(ptext_len > BLOCK_SIZE) {		// Processing 2 blocks at once
		packing(state, ptext, ptext + BLOCK_SIZE);
		for(int i = 0; i < 28; i += 4)
			QUADRUPLE_ROUND(state, rkey + i * 2, rconst + i);
		unpacking(ctext, ctext + BLOCK_SIZE, state);
		ptext += BLOCK_SIZE * 2;
		ctext += BLOCK_SIZE * 2;
		ptext_len -= BLOCK_SIZE * 2;
	}
	while(ptext_len > 0) {				// Processing a single block
		packing(state, ptext, ptext);
		for(int i = 0; i < 28; i += 4) 
			QUADRUPLE_ROUND(state, rkey + i * 2, rconst + i);
		unpacking(ctext, ctext, state);
		ptext += BLOCK_SIZE;
		ctext += BLOCK_SIZE;
		ptext_len -= BLOCK_SIZE;
	}
	return 0;
}

/****************************************************************************
* Decryption of 64-bit blocks. Note that 'ctext_len' must be a mutliple of 8.
****************************************************************************/
int gift64_decrypt_ecb(u8* ptext, const u8* ctext, u32 ctext_len, const u8* key) {
	u32 state[4], rkey[56];
	precompute_rkeys(rkey, key);
	while(ctext_len > BLOCK_SIZE) {		// Processing 2 blocks at a time
		packing(state, ctext, ctext + BLOCK_SIZE);
		for(int i = 24; i >= 0; i -= 4)
			INV_QUADRUPLE_ROUND(state, rkey + i*2, rconst + i);
		unpacking(ptext, ptext + BLOCK_SIZE, state);
		ptext += BLOCK_SIZE * 2;
		ctext += BLOCK_SIZE * 2;
		ctext_len -= BLOCK_SIZE * 2;
	}
	while(ctext_len > 0) {			// Processing a single block
		packing(state, ctext, ctext);
		for(int i = 24; i >= 0; i -= 4)
			INV_QUADRUPLE_ROUND(state, rkey + i*2, rconst + i);
		unpacking(ptext, ptext, state);
		ptext += BLOCK_SIZE;
		ctext += BLOCK_SIZE;
		ctext_len -= BLOCK_SIZE;
	}
	return 0;
}

/****************************************************************************
* Encryption of 64-bit blocks. Note that:
* - 'ptext_len' must be a mutliple of 8
* - 'ptext' is expected to be in a row-wise bitsliced representation.
****************************************************************************/
int giftb64_encrypt_ecb(u8* ctext, const u8* ptext, u32 ptext_len, const u8* key) {
	u32 state[4], rkey[56];
	precompute_rkeys(rkey, key);
	while(ptext_len > BLOCK_SIZE) {		// Processing 2 blocks at once
		packing_interleave(state, ptext, ptext + BLOCK_SIZE);
		for(int i = 0; i < 28; i += 4)
			QUADRUPLE_ROUND(state, rkey + i * 2, rconst + i);
		unpacking_interleave(ctext, ctext + BLOCK_SIZE, state);
		ptext += BLOCK_SIZE * 2;
		ctext += BLOCK_SIZE * 2;
		ptext_len -= BLOCK_SIZE * 2;
	}
	while(ptext_len > 0) {				// Processing a single block
		packing_interleave(state, ptext, ptext);
		for(int i = 0; i < 28; i += 4)
			QUADRUPLE_ROUND(state, rkey + i * 2, rconst + i);
		unpacking_interleave(ctext, ctext, state);
		ptext += BLOCK_SIZE;
		ctext += BLOCK_SIZE;
		ptext_len -= BLOCK_SIZE;
	}
	return 0;
}

/****************************************************************************
* Decryption of 64-bit blocks. Note that:
* - 'ctext_len' must be a mutliple of 8
* - 'ctext' is expected to be in a row-wise bitsliced representation.
****************************************************************************/
int giftb64_decrypt_ecb(u8* ptext, const u8* ctext, u32 ctext_len, const u8* key) {
	u32 state[4], rkey[56];
	precompute_rkeys(rkey, key);
	while(ctext_len > BLOCK_SIZE) {		// Processing 2 blocks at a time
		packing_interleave(state, ctext, ctext + BLOCK_SIZE);
		for(int i = 24; i >= 0; i-=4)
			INV_QUADRUPLE_ROUND(state, rkey + i * 2, rconst + i);
		unpacking_interleave(ptext, ptext + BLOCK_SIZE, state);
		ptext += BLOCK_SIZE * 2;
		ctext += BLOCK_SIZE * 2;
		ctext_len -= BLOCK_SIZE * 2;
	}
	while(ctext_len > 0) {			// Processing a single block
		packing_interleave(state, ctext, ctext);
		for(int i = 24; i >= 0; i -= 4)
			INV_QUADRUPLE_ROUND(state, rkey + i * 2, rconst + i);
		unpacking_interleave(ptext, ptext, state);
		ptext += BLOCK_SIZE;
		ctext += BLOCK_SIZE;
		ctext_len -= BLOCK_SIZE;
	}
	return 0;
}
