#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "key_des.h"

#include "searchCryptoKey.h"
#include "util.h"

#define DES_DUMP_RAW_KEY 		0

#define DES_KEY_NB_BIT 			64
#define DES_KEY_NB_BYTE 		8
#define DES_KEY_NB_WORD 		2

#define DES_ROUND_KEY_NB_BIT 	1024
#define DES_ROUND_KEY_NB_BYTE 	128
#define DES_ROUND_KEY_NB_WORD 	32

#define DES_NB_BLACK_LISTED_KEY 4

static const uint8_t black_listed_key[DES_NB_BLACK_LISTED_KEY][DES_KEY_NB_BYTE] = {
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0xff, 0xff, 0xff, 0xf0, 0xff, 0xff, 0xff, 0xf0},
	{0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xf0},
	{0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00}
};

static void des_get_key(const uint8_t* intern, uint8_t* key);

static const uint8_t p1[] = {
	7, 15, 23, 59, 55, 47, 39, 0,
	6, 14, 22, 58, 54, 46, 38, 0,
	5, 13, 21, 57, 53, 45, 37, 0,
	4, 12, 20, 56, 52, 44, 36, 0,
	3, 11, 19, 27, 51, 43, 35, 0,
	2, 10, 18, 26, 50, 42, 34, 0,
	1,  9, 17, 25, 49, 41, 33, 0,
	28, 8, 16, 24, 48, 40, 60, 0
};

static const uint8_t p2[] = {
	/* Round 1*/
	 5, 24,  7, 16,  6, 10, 20, 18,
	 0, 12,  3, 15, 23,  1,  9, 19,
	 2,  0, 14, 22, 11,  0, 13,  4,
	 0, 17, 21,  8, 47, 31, 27, 48,
	35, 41,  0, 46, 28,  0, 39, 32,
	25, 44,  0, 37, 34, 43, 29, 36,
	38, 45, 33, 26, 42,  0, 30, 40,

	/* Round 2 */
	 8,  5, 24,  7, 16,  6, 10, 20,
	18,  0, 12,  3, 15, 23,  1,  9,
	19,  2,  0, 14, 22, 11,  0, 13,
	 4,  0, 17, 21, 40, 47, 31, 27,
	48, 35, 41,  0, 46, 28,  0, 39,
	32, 25, 44,  0, 37, 34, 43, 29,
	36, 38, 45, 33, 26, 42,  0, 30,

	/* Round 3 */
	17, 21,  8,  5, 24,  7, 16,  6,
	10, 20, 18,  0, 12,  3, 15, 23,
	 1,  9, 19,  2,  0, 14, 22, 11,
	 0, 13,  4,  0,  0, 30, 40, 47,
	31, 27, 48, 35, 41,  0, 46, 28,
	 0, 39, 32, 25, 44,  0, 37, 34,
	43, 29, 36, 38, 45, 33, 26, 42,

	/* Round 4 */
	 4,  0, 17, 21,  8,  5, 24,  7,
	16,  6, 10, 20, 18,  0, 12,  3,
	15, 23,  1,  9, 19,  2,  0, 14,
	22, 11,  0, 13, 26, 42,  0, 30,
	40, 47, 31, 27, 48, 35, 41,  0,
	46, 28,  0, 39, 32, 25, 44,  0,
	37, 34, 43, 29, 36, 38, 45, 33,

	/* Round 5 */
	 0, 13,  4,  0, 17, 21,  8,  5,
	24,  7, 16,  6, 10, 20, 18,  0,
	12,  3, 15, 23,  1,  9, 19,  2,
	 0, 14, 22, 11, 45, 33, 26, 42,
	 0, 30, 40, 47, 31, 27, 48, 35,
	41,  0, 46, 28,  0, 39, 32, 25,
	44,  0, 37, 34, 43, 29, 36, 38,

	/* Round 6 */
	22, 11,  0, 13,  4,  0, 17, 21,
	 8,  5, 24,  7, 16,  6, 10, 20,
	18,  0, 12,  3, 15, 23,  1,  9,
	19,  2,  0, 14, 36, 38, 45, 33,
	26, 42,  0, 30, 40, 47, 31, 27,
	48, 35, 41,  0, 46, 28,  0, 39,
	32, 25, 44,  0, 37, 34, 43, 29,

	/* Round 7 */
	 0, 14, 22, 11,  0, 13,  4,  0,
	17, 21,  8,  5, 24,  7, 16,  6,
	10, 20, 18,  0, 12,  3, 15, 23,
	 1,  9, 19,  2, 43, 29, 36, 38,
	45, 33, 26, 42,  0, 30, 40, 47,
	31, 27, 48, 35, 41,  0, 46, 28,
	 0, 39, 32, 25, 44,  0, 37, 34,

	/* Round 8 */
	19,  2,  0, 14, 22, 11,  0, 13,
	 4,  0, 17, 21,  8,  5, 24,  7,
	16,  6, 10, 20, 18,  0, 12,  3,
	15, 23,  1,  9, 37, 34, 43, 29,
	36, 38, 45, 33, 26, 42,  0, 30,
	40, 47, 31, 27, 48, 35, 41,  0,
	46, 28,  0, 39, 32, 25, 44,  0,

	/* Round 9 */
	 9, 19,  2,  0, 14, 22, 11,  0,
	13,  4,  0, 17, 21,  8,  5, 24,
	 7, 16,  6, 10, 20, 18,  0, 12,
	 3, 15, 23,  1,  0, 37, 34, 43,
	29, 36, 38, 45, 33, 26, 42,  0,
	30, 40, 47, 31, 27, 48, 35, 41,
	 0, 46, 28,  0, 39, 32, 25, 44,

	/* Round 10 */
	23,  1,  9, 19,  2,  0, 14, 22,
	11,  0, 13,  4,  0, 17, 21,  8,
	 5, 24,  7, 16,  6, 10, 20, 18,
	 0, 12,  3, 15, 25, 44,  0, 37,
	34, 43, 29, 36, 38, 45, 33, 26,
	42,  0, 30, 40, 47, 31, 27, 48,
	35, 41,  0, 46, 28,  0, 39, 32,

	/* Round 11 */
	 3, 15, 23,  1,  9, 19,  2,  0,
	14, 22, 11,  0, 13,  4,  0, 17,
	21,  8,  5, 24,  7, 16,  6, 10,
	20, 18,  0, 12, 39, 32, 25, 44,
	 0, 37, 34, 43, 29, 36, 38, 45,
	33, 26, 42,  0, 30, 40, 47, 31,
	27, 48, 35, 41,  0, 46, 28,  0,

	/* Round 12 */
	 0, 12,  3, 15, 23,  1,  9, 19,
	 2,  0, 14, 22, 11,  0, 13,  4,
	 0, 17, 21,  8,  5, 24,  7, 16,
	 6, 10, 20, 18, 28,  0, 39, 32,
	25, 44,  0, 37, 34, 43, 29, 36,
	38, 45, 33, 26, 42,  0, 30, 40,
	47, 31, 27, 48, 35, 41,  0, 46,

	/* Round 13 */
	20, 18,  0, 12,  3, 15, 23,  1,
	 9, 19,  2,  0, 14, 22, 11,  0,
	13,  4,  0, 17, 21,  8,  5, 24,
	 7, 16,  6, 10,  0, 46, 28,  0,
	39, 32, 25, 44,  0, 37, 34, 43,
	29, 36, 38, 45, 33, 26, 42,  0,
	30, 40, 47, 31, 27, 48, 35, 41,

	/* Round 14 */
	 6, 10, 20, 18,  0, 12,  3, 15,
	23,  1,  9, 19,  2,  0, 14, 22,
	11,  0, 13,  4,  0, 17, 21,  8,
	 5, 24,  7, 16, 35, 41,  0, 46,
	28,  0, 39, 32, 25, 44,  0, 37,
	34, 43, 29, 36, 38, 45, 33, 26,
	42,  0, 30, 40, 47, 31, 27, 48,

	/* Round 15 */
	 7, 16,  6, 10, 20, 18,  0, 12,
	 3, 15, 23,  1,  9, 19,  2,  0,
	14, 22, 11,  0, 13,  4,  0, 17,
	21,  8,  5, 24, 27, 48, 35, 41,
	 0, 46, 28,  0, 39, 32, 25, 44,
	 0, 37, 34, 43, 29, 36, 38, 45,
	33, 26, 42,  0, 30, 40, 47, 31,

	/* Round 16 */
	24,  7, 16,  6, 10, 20, 18,  0,
	12,  3, 15, 23,  1,  9, 19,  2,
	 0, 14, 22, 11,  0, 13,  4,  0,
	17, 21,  8,  5, 31, 27, 48, 35,
	41,  0, 46, 28,  0, 39, 32, 25,
	44,  0, 37, 34, 43, 29, 36, 38,
	45, 33, 26, 42,  0, 30, 40, 47
};


static const uint32_t mask[] = {
	0x70bb7fff, 0xb0ffbdfd, 		/* 1  */
	0xb0ddbfff, 0xd0ffdefe, 		/* 2  */
	0x60f7efff, 0xf0bfb77f, 		/* 3  */
	0xd0fdfbbf, 0xf0efeddf, 		/* 4  */
	0x70fffe6f, 0xf07bfbf7, 		/* 5  */
	0xd0bfffdb, 0xf0defefd, 		/* 6  */
	0xf0efff76, 0xb0b77fff, 		/* 7  */
	0xf0fbbfdd, 0xe0eddfff, 		/* 8  */
	0xf0fddfee, 0xf0f6ef7f, 		/* 9  */
	0x70ffb7fb, 0xb0fdfbdf, 		/* 10 */
	0xd0ffedfe, 0x60fffef7, 		/* 11 */
	0xf07fbb7f, 0xd0bfffbd, 		/* 12 */
	0xf0dfeedf, 0xf0ef7f6f, 		/* 13 */
	0xf0b7fbf7, 0xf0fbdfdb, 		/* 14 */
	0xf0edfefd, 0xf0fef7f6, 		/* 15 */
	0xf076fffe, 0x70ff7bfb 			/* 16 */
};

#define ROTATE_R(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static inline void des_load_round_key_forward_fmt1(uint8_t* round_key, uint8_t* dst){
	dst[0] = round_key[3];
	dst[1] = round_key[7];
	dst[2] = round_key[2];
	dst[3] = round_key[6];
	dst[4] = round_key[1];
	dst[5] = round_key[5];
	dst[6] = round_key[0];
	dst[7] = round_key[4];
}

static inline void des_load_round_key_forward_fmt2(uint8_t* round_key, uint8_t* dst){
	uint32_t tmp1;
	uint32_t tmp2;

	tmp1 = __builtin_bswap32(*(uint32_t*)(round_key));
	tmp1 = ((tmp1 >> 7) & 0x01010101) | ((tmp1 >> 5) & 0x02020202) | ((tmp1 >> 3) & 0x04040404) | ((tmp1 >> 1) & 0x08080808) | ((tmp1 << 1) & 0x10101010) | ((tmp1 << 3) & 0x20202020);

	tmp2 = __builtin_bswap32(ROTATE_R(*(uint32_t*)(round_key + 4), 4));
	tmp2 = ((tmp2 >> 7) & 0x01010101) | ((tmp2 >> 5) & 0x02020202) | ((tmp2 >> 3) & 0x04040404) | ((tmp2 >> 1) & 0x08080808) | ((tmp2 << 1) & 0x10101010) | ((tmp2 << 3) & 0x20202020);

	dst[0] = (tmp1 >> 24) & 0x000000ff;
	dst[1] = (tmp2 >> 24) & 0x000000ff;
	dst[2] = (tmp1 >> 16) & 0x000000ff;
	dst[3] = (tmp2 >> 16) & 0x000000ff;
	dst[4] = (tmp1 >> 8 ) & 0x000000ff;
	dst[5] = (tmp2 >> 8 ) & 0x000000ff;
	dst[6] = tmp1 & 0x000000ff;
	dst[7] = tmp2 & 0x000000ff;
}

static inline void des_load_round_key_backward_fmt1(uint8_t* round_key, uint8_t* dst){
	dst[0] = round_key[3];
	dst[1] = round_key[7];
	dst[2] = round_key[2];
	dst[3] = round_key[6];
	dst[4] = round_key[1];
	dst[5] = round_key[5];
	dst[6] = round_key[0];
	dst[7] = round_key[4];
}

void search_des_key(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	size_t 		i;
	uint32_t 	j;
	uint32_t 	k;
	uint8_t* 	round_key;
	uint8_t 	key[DES_KEY_NB_BYTE];
	uint32_t 	found;
	uint8_t 	tmp2[8];
	uint32_t 	tmp1[2];
	uint32_t 	cd[2];
	#if DES_DUMP_RAW_KEY == 1
	char 		key_str[2*DES_KEY_NB_BYTE + 1];
	#endif

	if (chunk->size < DES_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->size - DES_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){

		/* FORWARD FMT1 */
		round_key = (uint8_t*)(chunk->buffer + i);

		/* 0 */
		des_load_round_key_forward_fmt1(round_key, tmp2);
		round_key += 8;

		memset(cd, 0, 8);

		for (k = 0; k < 28; k++){
			uint32_t index = p2[k];

			if (index){
				index --;
				*((uint8_t*)cd + (0 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		for (k = 0; k < 28; k++){
			uint32_t index = p2[k + 28];

			if (index){
				index --;
				*((uint8_t*)cd + (4 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		memcpy(tmp1, cd, 8);

		/* 1 */
		des_load_round_key_forward_fmt1(round_key, tmp2);
		round_key += 8;

		memset(cd, 0, 8);

		for (k = 0; k < 28; k++){
			uint32_t index = p2[56 + k];

			if (index){
				index --;
				*((uint8_t*)cd + (0 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		for (k = 0; k < 28; k++){
			uint32_t index = p2[56 + k + 28];

			if (index){
				index --;
				*((uint8_t*)cd + (4 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		found = 1;
		if (((tmp1[0] & mask[2]) != (cd[0] & mask[0])) || ((tmp1[1] & mask[3]) != (cd[1] & mask[1]))){
			found = 0;
		}

		tmp1[0] |= cd[0];
		tmp1[1] |= cd[1];

		if (found){
			for (k = 0; k < DES_NB_BLACK_LISTED_KEY; k++){
				if (!memcmp(tmp1, black_listed_key[k], DES_KEY_NB_BYTE)){
					found = 0;
					break;
				}
			}
		}

		/* - */
		for (j = 2; j < 16 && found; j++, round_key += 8){
			des_load_round_key_forward_fmt1(round_key, tmp2);

			memset(cd, 0, 8);

			for (k = 0; k < 28; k++){
				uint32_t index = p2[56*j + k];

				if (index){
					index --;
					*((uint8_t*)cd + (0 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
				}
			}

			for (k = 0; k < 28; k++){
				uint32_t index = p2[56 * j + k + 28];

				if (index){
					index --;
					*((uint8_t*)cd + (4 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
				}
			}

			if (((tmp1[0] & mask[2 * j]) != cd[0]) || ((tmp1[1] & mask[2 * j + 1]) != cd[1])){
				found = 0;
				break;
			}
		}

		if (found){
			des_get_key((uint8_t*)tmp1, key);
			searchCryptoKey_report_success((char*)key, DES_KEY_NB_BYTE, chunk->offset + i, _LITTLE_ENDIAN, "DES", "enc", chunk->file_name, printer);

			#if DES_DUMP_RAW_KEY == 1
			des_load_round_key_forward_fmt1((uint8_t*)(chunk->buffer + i), tmp2);
			sprintBuffer_raw(key_str, (char*)tmp1, DES_KEY_NB_BYTE);
			log_info_m("FORWARD FMT1 raw first round key: %s (turn DES_DUMP_RAW_KEY to 0 to disable this feature)", key_str);
			#endif
		}

		/* FORWARD FMT2 */
		round_key = (uint8_t*)(chunk->buffer + i);

		/* 0 */
		des_load_round_key_forward_fmt2(round_key, tmp2);
		round_key += 8;

		memset(cd, 0, 8);

		for (k = 0; k < 28; k++){
			uint32_t index = p2[k];

			if (index){
				index --;
				*((uint8_t*)cd + (0 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		for (k = 0; k < 28; k++){
			uint32_t index = p2[k + 28];

			if (index){
				index --;
				*((uint8_t*)cd + (4 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		memcpy(tmp1, cd, 8);

		/* 1 */
		des_load_round_key_forward_fmt2(round_key, tmp2);
		round_key += 8;

		memset(cd, 0, 8);

		for (k = 0; k < 28; k++){
			uint32_t index = p2[56 + k];

			if (index){
				index --;
				*((uint8_t*)cd + (0 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		for (k = 0; k < 28; k++){
			uint32_t index = p2[56 + k + 28];

			if (index){
				index --;
				*((uint8_t*)cd + (4 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		found = 1;
		if (((tmp1[0] & mask[2]) != (cd[0] & mask[0])) || ((tmp1[1] & mask[3]) != (cd[1] & mask[1]))){
			found = 0;
		}

		tmp1[0] |= cd[0];
		tmp1[1] |= cd[1];

		if (found){
			for (k = 0; k < DES_NB_BLACK_LISTED_KEY; k++){
				if (!memcmp(tmp1, black_listed_key[k], DES_KEY_NB_BYTE)){
					found = 0;
					break;
				}
			}
		}

		/* - */
		for (j = 2; j < 16 && found; j++, round_key += 8){
			des_load_round_key_forward_fmt2(round_key, tmp2);

			memset(cd, 0, 8);

			for (k = 0; k < 28; k++){
				uint32_t index = p2[56*j + k];

				if (index){
					index --;
					*((uint8_t*)cd + (0 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
				}
			}

			for (k = 0; k < 28; k++){
				uint32_t index = p2[56 * j + k + 28];

				if (index){
					index --;
					*((uint8_t*)cd + (4 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
				}
			}

			if (((tmp1[0] & mask[2 * j]) != cd[0]) || ((tmp1[1] & mask[2 * j + 1]) != cd[1])){
				found = 0;
				break;
			}
		}

		if (found){
			des_get_key((uint8_t*)tmp1, key);
			searchCryptoKey_report_success((char*)key, DES_KEY_NB_BYTE, chunk->offset + i, _LITTLE_ENDIAN, "DES", "enc", chunk->file_name, printer);

			#if DES_DUMP_RAW_KEY == 1
			des_load_round_key_forward_fmt2((uint8_t*)(chunk->buffer + i), tmp2);
			sprintBuffer_raw(key_str, (char*)tmp1, DES_KEY_NB_BYTE);
			log_info_m("FORWARD FMT2 raw first round key: %s (turn DES_DUMP_RAW_KEY to 0 to disable this feature)", key_str);
			#endif
		}

		/* BACKWARD FMT1 */
		round_key = (uint8_t*)(chunk->buffer + i + 8 * 15);

		/* 0 */
		des_load_round_key_backward_fmt1(round_key, tmp2);
		round_key -= 8;

		memset(cd, 0, 8);

		for (k = 0; k < 28; k++){
			uint32_t index = p2[k];

			if (index){
				index --;
				*((uint8_t*)cd + (0 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		for (k = 0; k < 28; k++){
			uint32_t index = p2[k + 28];

			if (index){
				index --;
				*((uint8_t*)cd + (4 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		memcpy(tmp1, cd, 8);

		/* 1 */
		des_load_round_key_backward_fmt1(round_key, tmp2);
		round_key -= 8;

		memset(cd, 0, 8);

		for (k = 0; k < 28; k++){
			uint32_t index = p2[56 + k];

			if (index){
				index --;
				*((uint8_t*)cd + (0 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		for (k = 0; k < 28; k++){
			uint32_t index = p2[56 + k + 28];

			if (index){
				index --;
				*((uint8_t*)cd + (4 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
			}
		}

		found = 1;
		if (((tmp1[0] & mask[2]) != (cd[0] & mask[0])) || ((tmp1[1] & mask[3]) != (cd[1] & mask[1]))){
			found = 0;
		}

		tmp1[0] |= cd[0];
		tmp1[1] |= cd[1];

		if (found){
			for (k = 0; k < DES_NB_BLACK_LISTED_KEY; k++){
				if (!memcmp(tmp1, black_listed_key[k], DES_KEY_NB_BYTE)){
					found = 0;
					break;
				}
			}
		}

		/* - */
		for (j = 2; j < 16 && found ; j++, round_key -= 8){
			des_load_round_key_backward_fmt1(round_key, tmp2);

			memset(cd, 0, 8);

			for (k = 0; k < 28; k++){
				uint32_t index = p2[56*j + k];

				if (index){
					index --;
					*((uint8_t*)cd + (0 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
				}
			}

			for (k = 0; k < 28; k++){
				uint32_t index = p2[56 *j+ k + 28];

				if (index){
					index --;
					*((uint8_t*)cd + (4 + (k / 8))) |= ((tmp2[index / 6] >> (5 - (index % 6))) & 0x01) << (7 - (k % 8));
				}
			}

			if (((tmp1[0] & mask[2 * j]) != cd[0]) || ((tmp1[1] & mask[2 * j + 1]) != cd[1])){
				found = 0;
				break;
			}
		}

		if (found){
			des_get_key((uint8_t*)tmp1, key);
			searchCryptoKey_report_success((char*)key, DES_KEY_NB_BYTE, chunk->offset + i, _LITTLE_ENDIAN, "DES", "dec", chunk->file_name, printer);

			#if DES_DUMP_RAW_KEY == 1
			des_load_round_key_backward_fmt1((uint8_t*)(chunk->buffer + i + 8 * 15), tmp2);
			sprintBuffer_raw(key_str, (char*)tmp1, DES_KEY_NB_BYTE);
			log_info_m("BACKWARD FMT 1 raw first round key: %s (turn DES_DUMP_RAW_KEY to 0 to disable this feature)", key_str);
			#endif
		}
	}
}

static void des_get_key(const uint8_t* intern, uint8_t* key){
	uint32_t j;

	memset(key, 0, DES_KEY_NB_BYTE);
	for (j = 0; j < 64; j++){
		uint32_t index = p1[j];

		if (index){
			index --;
			key[j >> 3] |= ((intern[index >> 3] >> (7 - (index & 0x00000007))) & 0x00000001) << (7 - (j & 0X00000007));
		}
	}

	for (j = 0; j < 8; j++){
		uint8_t a = key[j] ^ (key[j] >> 4);
		if (((a ^ (a >> 1) ^ (a >> 2) ^ (a >> 3)) & 0x01) != 0x01){
			key[j] ^= 0x01;
		}
	}
}
