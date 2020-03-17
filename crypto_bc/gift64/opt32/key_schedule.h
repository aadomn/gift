#ifndef KEYSCHEDULE_H_
#define KEYSCHEDULE_H_

#define TRANSPOSE_U32(x) ({												\
	tmp = x & 0x88442211;												\
	tmp |= ((x & 0x44221100) >> 7);										\
	tmp |= ((x & 0x22110000) >> 14);									\
	tmp |= ((x & 0x11000000) >> 21);									\
	tmp |= ((x & 0x00884422) << 7);										\
	tmp |= ((x & 0x00008844) << 14);									\
	tmp |= ((x & 0x00000088) << 21);									\
	x = tmp;															\
})

#define REARRANGE_KEYWORD_0_1(x, y) ({									\
	(((y) & 0xf0) << 20)	| (((x) & 0x0f) << 16)	|					\
	(((x) & 0xf0) << 4)		| ((y) & 0x0f);								\
})

#define REARRANGE_KEYWORD_2_3(x, y) ({									\
	(((x) & 0xf0) << 20)	| (((x) & 0x0f) << 16)	|					\
	(((y) & 0xf0) << 4)		| ((y) & 0x0f);								\
})

#endif  // KEYSCHEDULE_H_