#include <stdlib.h>
#include <stdio.h>

#include "key_serpent.h"

#include "searchCryptoKey.h"
#include "util.h"

#define SERPENT_ROUND_KEY_NB_BIT 	4224
#define SERPENT_ROUND_KEY_NB_BYTE 	528
#define SERPENT_ROUND_KEY_NB_WORD 	132

#define SERPENT_KEY_MAX_NB_BIT 		256
#define SERPENT_KEY_MAX_NB_BYTE 	32
#define SERPENT_KEY_MAX_NB_WORD 	8

#define SERPENT_GOLDEN_RATIO 0x9e3779b9

#define ROTATE_R(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTATE_L(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define SBoxD0(x0, x1, x2, x3, y0, y1, y2, y3) 		\
	{ 												\
		uint32_t T0 = x0; 							\
		uint32_t T1 = x1; 							\
		uint32_t T2 = x2; 							\
		uint32_t T3 = x3; 							\
		uint32_t T4; 								\
													\
		T2 = ~T2; 									\
		T4  = T1; 									\
		T1 |= T0; 									\
		T4 = ~T4; 									\
		T1 ^= T2; 									\
		T2 |= T4; 									\
		T1 ^= T3; 									\
		T0 ^= T4; 									\
		T2 ^= T0; 									\
		T0 &= T3; 									\
		T4 ^= T0; 									\
		T0 |= T1; 									\
		T0 ^= T2; 									\
		T3 ^= T4; 									\
		T2 ^= T1; 									\
		T3 ^= T0; 									\
		T3 ^= T1; 									\
		T2 &= T3; 									\
		T4 ^= T2; 									\
													\
		y0 = T0; 									\
		y1 = T4; 									\
		y2 = T1; 									\
		y3 = T3; 									\
	}

#define SBoxD1(x0, x1, x2, x3, y0, y1, y2, y3) 		\
	{ 												\
		uint32_t T0 = x0; 							\
		uint32_t T1 = x1; 							\
		uint32_t T2 = x2; 							\
		uint32_t T3 = x3; 							\
		uint32_t T4; 								\
													\
		T4  = T1; 									\
		T1 ^= T3; 									\
		T3 &= T1; 									\
		T4 ^= T2; 									\
		T3 ^= T0; 									\
		T0 |= T1; 									\
		T2 ^= T3; 									\
		T0 ^= T4; 									\
		T0 |= T2; 									\
		T1 ^= T3; 									\
		T0 ^= T1; 									\
		T1 |= T3; 									\
		T1 ^= T0; 									\
		T4 = ~T4; 									\
		T4 ^= T1; 									\
		T1 |= T0; 									\
		T1 ^= T0; 									\
		T1 |= T4; 									\
		T3 ^= T1; 									\
													\
		y0 = T4; 									\
		y1 = T0; 									\
		y2 = T3; 									\
		y3 = T2; 									\
	}

#define SBoxD2(x0, x1, x2, x3, y0, y1, y2, y3) 		\
	{ 												\
		uint32_t T0 = x0; 							\
		uint32_t T1 = x1; 							\
		uint32_t T2 = x2; 							\
		uint32_t T3 = x3; 							\
		uint32_t T4; 								\
													\
		T2 ^= T3; 									\
		T3 ^= T0; 									\
		T4  = T3; 									\
		T3 &= T2; 									\
		T3 ^= T1; 									\
		T1 |= T2; 									\
		T1 ^= T4; 									\
		T4 &= T3; 									\
		T2 ^= T3; 									\
		T4 &= T0; 									\
		T4 ^= T2; 									\
		T2 &= T1; 									\
		T2 |= T0; 									\
		T3 = ~T3; 									\
		T2 ^= T3; 									\
		T0 ^= T3; 									\
		T0 &= T1; 									\
		T3 ^= T4; 									\
		T3 ^= T0; 									\
													\
		y0 = T1; 									\
		y1 = T4; 									\
		y2 = T2; 									\
		y3 = T3; 									\
	}

#define SBoxD3(x0, x1, x2, x3, y0, y1, y2, y3) 		\
	{ 												\
		uint32_t T0 = x0; 							\
		uint32_t T1 = x1; 							\
		uint32_t T2 = x2; 							\
		uint32_t T3 = x3; 							\
		uint32_t T4; 								\
													\
		T4  = T2; 									\
		T2 ^= T1; 									\
		T0 ^= T2; 									\
		T4 &= T2; 									\
		T4 ^= T0; 									\
		T0 &= T1; 									\
		T1 ^= T3; 									\
		T3 |= T4; 									\
		T2 ^= T3; 									\
		T0 ^= T3; 									\
		T1 ^= T4; 									\
		T3 &= T2; 									\
		T3 ^= T1; 									\
		T1 ^= T0; 									\
		T1 |= T2; 									\
		T0 ^= T3; 									\
		T1 ^= T4; 									\
		T0 ^= T1; 									\
													\
		y0 = T2; 									\
		y1 = T1; 									\
		y2 = T3; 									\
		y3 = T0; 									\
	}

#define SBoxD4(x0, x1, x2, x3, y0, y1, y2, y3) 		\
	{ 												\
		uint32_t T0 = x0; 							\
		uint32_t T1 = x1; 							\
		uint32_t T2 = x2; 							\
		uint32_t T3 = x3; 							\
		uint32_t T4; 								\
													\
		T4  = T2; 									\
		T2 &= T3; 									\
		T2 ^= T1; 									\
		T1 |= T3; 									\
		T1 &= T0; 									\
		T4 ^= T2; 									\
		T4 ^= T1; 									\
		T1 &= T2; 									\
		T0 = ~T0; 									\
		T3 ^= T4; 									\
		T1 ^= T3; 									\
		T3 &= T0; 									\
		T3 ^= T2; 									\
		T0 ^= T1; 									\
		T2 &= T0; 									\
		T3 ^= T0; 									\
		T2 ^= T4; 									\
		T2 |= T3; 									\
		T3 ^= T0; 									\
		T2 ^= T1; 									\
													\
		y0 = T0; 									\
		y1 = T3; 									\
		y2 = T2; 									\
		y3 = T4; 									\
	}

#define SBoxD5(x0, x1, x2, x3, y0, y1, y2, y3) 		\
	{ 												\
		uint32_t T0 = x0; 							\
		uint32_t T1 = x1; 							\
		uint32_t T2 = x2; 							\
		uint32_t T3 = x3; 							\
		uint32_t T4; 								\
													\
		T1 = ~T1; 									\
		T4  = T3; 									\
		T2 ^= T1; 									\
		T3 |= T0; 									\
		T3 ^= T2; 									\
		T2 |= T1; 									\
		T2 &= T0; 									\
		T4 ^= T3; 									\
		T2 ^= T4; 									\
		T4 |= T0; 									\
		T4 ^= T1; 									\
		T1 &= T2; 									\
		T1 ^= T3; 									\
		T4 ^= T2; 									\
		T3 &= T4; 									\
		T4 ^= T1; 									\
		T3 ^= T4; 									\
		T4 = ~T4; 									\
		T3 ^= T0; 									\
													\
		y0 = T1; 									\
		y1 = T4; 									\
		y2 = T3; 									\
		y3 = T2; 									\
	}

#define SBoxD6(x0, x1, x2, x3, y0, y1, y2, y3) 		\
	{ 												\
		uint32_t T0 = x0; 							\
		uint32_t T1 = x1; 							\
		uint32_t T2 = x2; 							\
		uint32_t T3 = x3; 							\
		uint32_t T4; 								\
													\
		T0 ^= T2; 									\
		T4  = T2; 									\
		T2 &= T0; 									\
		T4 ^= T3; 									\
		T2 = ~T2; 									\
		T3 ^= T1; 									\
		T2 ^= T3; 									\
		T4 |= T0; 									\
		T0 ^= T2; 									\
		T3 ^= T4; 									\
		T4 ^= T1; 									\
		T1 &= T3; 									\
		T1 ^= T0; 									\
		T0 ^= T3; 									\
		T0 |= T2; 									\
		T3 ^= T1; 									\
		T4 ^= T0; 									\
													\
		y0 = T1; 									\
		y1 = T2; 									\
		y2 = T4; 									\
		y3 = T3; 									\
	}

#define SBoxD7(x0, x1, x2, x3, y0, y1, y2, y3) 		\
	{ 												\
		uint32_t T0 = x0; 							\
		uint32_t T1 = x1; 							\
		uint32_t T2 = x2; 							\
		uint32_t T3 = x3; 							\
		uint32_t T4; 								\
													\
		T4  = T2; 									\
		T2 ^= T0; 									\
		T0 &= T3; 									\
		T4 |= T3; 									\
		T2 = ~T2; 									\
		T3 ^= T1; 									\
		T1 |= T0; 									\
		T0 ^= T2; 									\
		T2 &= T4; 									\
		T3 &= T4; 									\
		T1 ^= T2; 									\
		T2 ^= T0; 									\
		T0 |= T2; 									\
		T4 ^= T1; 									\
		T0 ^= T3; 									\
		T3 ^= T4; 									\
		T4 |= T0; 									\
		T3 ^= T2; 									\
		T4 ^= T2; 									\
													\
		y0 = T3; 									\
		y1 = T0; 									\
		y2 = T1; 									\
		y3 = T4; 									\
	}

void search_serpent_key(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	size_t 		i;
	uint32_t* 	round_key;
	uint32_t 	tmp[SERPENT_ROUND_KEY_NB_WORD];
	uint32_t 	key[SERPENT_KEY_MAX_NB_WORD];

	if (chunk->size < SERPENT_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->size - SERPENT_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key = (uint32_t*)(chunk->buffer + i);

		SBoxD3(round_key[0  ], round_key[1  ], round_key[2  ], round_key[3  ], tmp[0  ], tmp[1  ], tmp[2  ], tmp[3  ])
		SBoxD2(round_key[4  ], round_key[5  ], round_key[6  ], round_key[7  ], tmp[4  ], tmp[5  ], tmp[6  ], tmp[7  ]);

		#define validate_round_key(i, box) 																										\
		box(round_key[i], round_key[i + 1], round_key[i + 2], round_key[i + 3], tmp[i], tmp[i + 1], tmp[i + 2], tmp[i + 3]); 					\
		if (tmp[(i) + 0] != ROTATE_L(tmp[(i) - 8] ^ tmp[(i) - 5] ^ tmp[(i) - 3] ^ tmp[(i) - 1] ^ SERPENT_GOLDEN_RATIO ^ ((i) + 0) , 11)){ 		\
			continue; 																															\
		} 																																		\
		if (tmp[(i) + 1] != ROTATE_L(tmp[(i) - 7] ^ tmp[(i) - 4] ^ tmp[(i) - 2] ^ tmp[(i) - 0] ^ SERPENT_GOLDEN_RATIO ^ ((i) + 1) , 11)){ 		\
			continue; 																															\
		} 																																		\
		if (tmp[(i) + 2] != ROTATE_L(tmp[(i) - 6] ^ tmp[(i) - 3] ^ tmp[(i) - 1] ^ tmp[(i) + 1] ^ SERPENT_GOLDEN_RATIO ^ ((i) + 2) , 11)){ 		\
			continue; 																															\
		} 																																		\
		if (tmp[(i) + 3] != ROTATE_L(tmp[(i) - 5] ^ tmp[(i) - 2] ^ tmp[(i) - 0] ^ tmp[(i) + 2] ^ SERPENT_GOLDEN_RATIO ^ ((i) + 3) , 11)){ 		\
			continue; 																															\
		}

		validate_round_key(8  , SBoxD1)
		validate_round_key(12 , SBoxD0)
		validate_round_key(16 , SBoxD7)
		validate_round_key(20 , SBoxD6)
		validate_round_key(24 , SBoxD5)
		validate_round_key(28 , SBoxD4)
		validate_round_key(32 , SBoxD3)
		validate_round_key(36 , SBoxD2)
		validate_round_key(40 , SBoxD1)
		validate_round_key(44 , SBoxD0)
		validate_round_key(48 , SBoxD7)
		validate_round_key(52 , SBoxD6)
		validate_round_key(56 , SBoxD5)
		validate_round_key(60 , SBoxD4)
		validate_round_key(64 , SBoxD3)
		validate_round_key(68 , SBoxD2)
		validate_round_key(72 , SBoxD1)
		validate_round_key(76 , SBoxD0)
		validate_round_key(80 , SBoxD7)
		validate_round_key(84 , SBoxD6)
		validate_round_key(88 , SBoxD5)
		validate_round_key(92 , SBoxD4)
		validate_round_key(96 , SBoxD3)
		validate_round_key(100, SBoxD2)
		validate_round_key(104, SBoxD1)
		validate_round_key(108, SBoxD0)
		validate_round_key(112, SBoxD7)
		validate_round_key(116, SBoxD6)
		validate_round_key(120, SBoxD5)
		validate_round_key(124, SBoxD4)
		validate_round_key(128, SBoxD3)

		key[7] = ROTATE_R(tmp[7], 11) ^ tmp[2] ^ tmp[4] ^ tmp[6] ^ SERPENT_GOLDEN_RATIO ^ 7;
		key[6] = ROTATE_R(tmp[6], 11) ^ tmp[1] ^ tmp[3] ^ tmp[5] ^ SERPENT_GOLDEN_RATIO ^ 6;
		key[5] = ROTATE_R(tmp[5], 11) ^ tmp[0] ^ tmp[2] ^ tmp[4] ^ SERPENT_GOLDEN_RATIO ^ 5;
		key[4] = ROTATE_R(tmp[4], 11) ^ key[7] ^ tmp[1] ^ tmp[3] ^ SERPENT_GOLDEN_RATIO ^ 4;
		key[3] = ROTATE_R(tmp[3], 11) ^ key[6] ^ tmp[0] ^ tmp[2] ^ SERPENT_GOLDEN_RATIO ^ 3;
		key[2] = ROTATE_R(tmp[2], 11) ^ key[5] ^ key[7] ^ tmp[1] ^ SERPENT_GOLDEN_RATIO ^ 2;
		key[1] = ROTATE_R(tmp[1], 11) ^ key[4] ^ key[6] ^ tmp[0] ^ SERPENT_GOLDEN_RATIO ^ 1;
		key[0] = ROTATE_R(tmp[0], 11) ^ key[3] ^ key[5] ^ key[7] ^ SERPENT_GOLDEN_RATIO ^ 0;

		searchCryptoKey_report_success((char*)key, SERPENT_KEY_MAX_NB_BYTE, chunk->offset + i, _LITTLE_ENDIAN, "Serpent", "-", chunk->file_name, printer);
	}

	return;
}
