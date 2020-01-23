#ifndef GIFT64_H_
#define GIFT64_H_

#define ROR(x,y) 		(((x) >> (y)) | ((x) << (32 - (y))))
#define NIBBLE_ROR_1(x) ((((x) >> 1) & 0x77777777) | (((x) & 0x11111111) << 3))
#define NIBBLE_ROR_2(x) ((((x) >> 2) & 0x33333333) | (((x) & 0x33333333) << 2))
#define NIBBLE_ROR_3(x) ((((x) >> 3) & 0x11111111) | (((x) & 0x77777777) << 1))

#define SWAPMOVE(a, b, mask, n)	({											\
	tmp = (b ^ (a >> n)) & mask;											\
	b ^= tmp;																\
	a ^= (tmp << n);														\
})

#define SBOX(s0, s1, s2, s3)												\
	s1 ^= s0 & s2;															\
	s0 ^= s1 & s3;															\
	s2 ^= s0 | s1;															\
	s3 ^= s2;																\
	s1 ^= s3;																\
	s2 ^= s0 & s1;

#define INV_SBOX(s0, s1, s2, s3)											\
	s2 ^= s3 & s1;															\
	s1 ^= s0;																\
	s0 ^= s2;																\
	s2 ^= s3 | s1;															\
	s3 ^= s1 & s0;															\
	s1 ^= s3 & s2;

#define QUADRUPLE_ROUND(state, rkey, rconst) ({								\
	SBOX(state[0], state[1], state[2], state[3]);							\
	state[1] = NIBBLE_ROR_1(state[1]);										\
	state[2] = NIBBLE_ROR_2(state[2]);										\
	state[0] = NIBBLE_ROR_3(state[0]);										\
	state[3] ^= (rkey)[0];													\
	state[1] ^= (rkey)[1];													\
	state[0] ^= (rconst)[0];												\
	SBOX(state[3], state[1], state[2], state[0]);							\
	state[1] = ROR(state[1], 8);											\
	state[2] = ROR(state[2], 16);											\
	state[3] = ROR(state[3], 24);											\
	state[0] ^= (rkey)[2];													\
	state[1] ^= (rkey)[3];													\
	state[3] ^= (rconst)[1];												\
	SBOX(state[0], state[1], state[2], state[3]);							\
	state[1] = NIBBLE_ROR_3(state[1]);										\
	state[2] = NIBBLE_ROR_2(state[2]);										\
	state[0] = NIBBLE_ROR_1(state[0]);										\
	state[3] ^= (rkey)[4];													\
	state[1] ^= (rkey)[5];													\
	state[0] ^= (rconst)[2];												\
	SBOX(state[3], state[1], state[2], state[0]);							\
	state[1] = ROR(state[1], 24);											\
	state[2] = ROR(state[2], 16);											\
	state[3] = ROR(state[3], 8);											\
	state[0] ^= (rkey)[6];													\
	state[1] ^= (rkey)[7];													\
	state[3] ^= (rconst)[3];												\
})

#define INV_QUADRUPLE_ROUND(state, rkey, rconst) ({							\
	state[0] ^= (rkey)[6];													\
	state[1] ^= (rkey)[7];													\
	state[3] ^= (rconst)[3];												\
	state[1] = ROR(state[1], 8);											\
	state[2] = ROR(state[2], 16);											\
	state[3] = ROR(state[3], 24);											\
	INV_SBOX(state[0], state[1], state[2],  state[3]);						\
	state[3] ^= (rkey)[4];													\
	state[1] ^= (rkey)[5];													\
	state[0] ^= (rconst)[2];												\
	state[1] = NIBBLE_ROR_1(state[1]);										\
	state[2] = NIBBLE_ROR_2(state[2]);										\
	state[0] = NIBBLE_ROR_3(state[0]);										\
	INV_SBOX(state[3], state[1], state[2], state[0]);						\
	state[0] ^= (rkey)[2];													\
	state[1] ^= (rkey)[3];													\
	state[3] ^= (rconst)[1];												\
	state[1] = ROR(state[1], 24);											\
	state[2] = ROR(state[2], 16);											\
	state[3] = ROR(state[3], 8);											\
	INV_SBOX(state[0], state[1], state[2],  state[3]);						\
	state[3] ^= (rkey)[0];													\
	state[1] ^= (rkey)[1];													\
	state[0] ^= (rconst)[0];												\
	state[1] = NIBBLE_ROR_3(state[1]);										\
	state[2] = NIBBLE_ROR_2(state[2]);										\
	state[0] = NIBBLE_ROR_1(state[0]);										\
	INV_SBOX(state[3], state[1], state[2],  state[0]);						\
})

#endif  // GIFT64_H_