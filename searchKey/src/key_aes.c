#include <stdlib.h>
#include <stdio.h>

#include "key_aes.h"

#include "util.h"

#define AES128_KEY_NB_BYTE			16
#define AES128_ROUND_KEY_NB_BYTE 	176
#define AES128_ROUND_KEY_NB_WORD 	44
#define AES128_NB_ROUND				10

#define AES192_KEY_NB_BYTE			24
#define AES192_ROUND_KEY_NB_BYTE 	208
#define AES192_ROUND_KEY_NB_WORD 	52
#define AES192_NB_ROUND				12

#define AES256_KEY_NB_BYTE			32
#define AES256_ROUND_KEY_NB_BYTE 	240
#define AES256_ROUND_KEY_NB_WORD 	60
#define AES256_NB_ROUND				14

#define RORc_big_endian(x, y) 		(((x) >> ((y) & 0x0000001f)) | ((x) << (0x00000020 - ((y) & 0x0000001f))))
#define RORc_little_endian(x, y) 	(((x) << ((y) & 0x0000001f)) | ((x) >> (0x00000020 - ((y) & 0x0000001f))))

#define setup_mix_big_endian(v) 	(((uint32_t)S[((v) >> 16 ) & 0x000000ff] << 24) | ((uint32_t)S[((v) >> 8 ) & 0x000000ff] << 16) | ((uint32_t)S[(v) & 0x000000ff] << 8) | (uint32_t)S[(v) >> 24])
#define setup_mix_little_endian(v) 	(((uint32_t)S[((v) >> 16 ) & 0x000000ff] << 8) | (uint32_t)S[((v) >> 8 ) & 0x000000ff] | ((uint32_t)S[(v) & 0x000000ff] << 24) | ((uint32_t)S[(v) >> 24 ] << 16))

static const uint32_t rcon_big_endian[] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000,
	0x36000000
};

static const uint32_t rcon_little_endian[] = {
	0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x0000001B,
	0x00000036
};

static const uint8_t S[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static inline uint32_t column0_big_endian(uint32_t x){
	uint32_t result;
	uint32_t mask;

	result = (x << 25) | ((x << 16) & 0x00ff0000) | ((x << 8) & 0x0000ff00) | (((x << 1) ^ x) & 0x000000ff);
	mask = (~(((x >> 7) & 0x00000001) + 0xffffffff)) & 0x1b00001b;
	result ^= mask;

	return result;
}

static inline uint32_t column1_big_endian(uint32_t x){
	uint32_t result;
	uint32_t mask;

	result = ((x << 25) ^ (x << 24)) | ((x << 17) & 0x00ff0000) | ((x << 8) & 0x0000ff00) | (x & 0x000000ff);
	mask = (~(((x >> 7) & 0x00000001) + 0xffffffff)) & 0x1b1b0000;
	result ^= mask;

	return result;
}

static inline uint32_t column2_big_endian(uint32_t x){
	uint32_t result;
	uint32_t mask;

	result = (x << 24) | (((x << 17) ^ (x << 16)) & 0x00ff0000) | ((x << 9) & 0x0000ff00) | (x & 0x000000ff);
	mask = (~(((x >> 7) & 0x00000001) + 0xffffffff)) & 0x001b1b00;
	result ^= mask;

	return result;
}

static inline uint32_t column3_big_endian(uint32_t x){
	uint32_t result;
	uint32_t mask;

	result = (x << 24) | ((x << 16) & 0x00ff0000) | (((x << 9) ^ (x << 8)) & 0x0000ff00) | ((x << 1) & 0x000000ff);
	mask = (~(((x >> 7) & 0x00000001) + 0xffffffff)) & 0x00001b1b;
	result ^= mask;

	return result;
}

static inline uint32_t column0_little_endian(uint32_t x){
	uint32_t result;
	uint32_t mask;

	result = ((x << 25) ^ (x << 24)) | ((x << 16) & 0x00ff0000) | ((x << 8) & 0x0000ff00) | ((x << 1) & 0x000000ff);
	mask = (~(((x >> 7) & 0x00000001) + 0xffffffff)) & 0x1b00001b;
	result ^= mask;

	return result;
}

static inline uint32_t column1_little_endian(uint32_t x){
	uint32_t result;
	uint32_t mask;

	result = (x << 24) | ((x << 16) & 0x00ff0000) | ((x << 9) & 0x0000ff00) | ((x ^ (x << 1)) & 0x000000ff);
	mask = (~(((x >> 7) & 0x00000001) + 0xffffffff)) & 0x00001b1b;
	result ^= mask;

	return result;
}

static inline uint32_t column2_little_endian(uint32_t x){
	uint32_t result;
	uint32_t mask;

	result = (x << 24) | ((x << 17) & 0x00ff0000) | (((x << 9) ^ (x << 8)) & 0x0000ff00) | (x & 0x000000ff);
	mask = (~(((x >> 7) & 0x00000001) + 0xffffffff)) & 0x001b1b00;
	result ^= mask;

	return result;
}

static inline uint32_t column3_little_endian(uint32_t x){
	uint32_t result;
	uint32_t mask;

	result = (x << 25) | (((x << 17) ^ (x << 16)) & 0x00ff0000) | ((x << 8) & 0x0000ff00) | (x & 0x000000ff);
	mask = (~(((x >> 7) & 0x00000001) + 0xffffffff)) & 0x1b1b0000;
	result ^= mask;

	return result;
}

#define mix_column_big_endian(x) (column0_big_endian(x >> 24) ^ column1_big_endian(x >> 16) ^ column2_big_endian(x >> 8) ^ column3_big_endian(x))
#define mix_column_little_endian(x) (column0_little_endian(x) ^ column1_little_endian(x >> 8) ^ column2_little_endian(x >> 16) ^ column3_little_endian(x >> 24))

void search_AES128_enc_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key;
	uint32_t 	tmp;
	uint8_t 	found;
	char 		key_str[2*AES128_KEY_NB_BYTE + 1];

	if (chunk->length < AES128_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES128_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key = (uint32_t*)(chunk->buffer + i);
		found = 1;

		for (j = 0; j < AES128_NB_ROUND; j++){
			tmp = round_key[4 * (j + 1) - 1];
			if (round_key[4 * (j + 1) + 0] != (round_key[4 * j + 0] ^ setup_mix_big_endian(tmp) ^ rcon_big_endian[j])){
				found = 0;
				break;
			}
			if (round_key[4 * (j + 1) + 1] != (round_key[4 * j + 1] ^ round_key[4 * (j + 1) + 0])){
				found = 0;
				break;
			}
			if (round_key[4 * (j + 1) + 2] != (round_key[4 * j + 2] ^ round_key[4 * (j + 1) + 1])){
				found = 0;
				break;
			}
			if (round_key[4 * (j + 1) + 3] != (round_key[4 * j + 3] ^ round_key[4 * (j + 1) + 2])){
				found = 0;
				break;
			}
		}

		if (found){
			sprintBuffer_raw_inv_endian(key_str, chunk->buffer + i, AES128_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES128", "b", "enc", chunk->offset + i, key_str);
		}
	}

	return;
}

void search_AES128_dec_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key_dec;
	uint32_t 	round_key_enc[AES128_ROUND_KEY_NB_WORD - 4];
	uint8_t 	found;
	char 		key_str[2*AES128_KEY_NB_BYTE + 1];

	if (chunk->length < AES128_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES128_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key_dec = (uint32_t*)(chunk->buffer + i);
		found = 1;

		round_key_enc[0] = round_key_dec[0];
		round_key_enc[1] = round_key_dec[1];
		round_key_enc[2] = round_key_dec[2];
		round_key_enc[3] = round_key_dec[3];

		for (j = 0; j < AES128_NB_ROUND - 1; j++){
			round_key_enc[4 * (j + 1) + 0] = round_key_enc[4 * j + 0] ^ setup_mix_big_endian(round_key_enc[4 * (j + 1) - 1]) ^ rcon_big_endian[j];
			if (mix_column_big_endian(round_key_dec[4 * (j + 1) + 0]) != round_key_enc[4 * (j + 1) + 0]){
				found = 0;
				break;
			}
			round_key_enc[4 * (j + 1) + 1] = round_key_enc[4 * j + 1] ^ round_key_enc[4 * (j + 1) + 0];
			if (mix_column_big_endian(round_key_dec[4 * (j + 1) + 1]) != round_key_enc[4 * (j + 1) + 1]){
				found = 0;
				break;
			}
			round_key_enc[4 * (j + 1) + 2] = round_key_enc[4 * j + 2] ^ round_key_enc[4 * (j + 1) + 1];
			if (mix_column_big_endian(round_key_dec[4 * (j + 1) + 2]) != round_key_enc[4 * (j + 1) + 2]){
				found = 0;
				break;
			}
			round_key_enc[4 * (j + 1) + 3] = round_key_enc[4 * j + 3] ^ round_key_enc[4 * (j + 1) + 2];
			if (mix_column_big_endian(round_key_dec[4 * (j + 1) + 3]) != round_key_enc[4 * (j + 1) + 3]){
				found = 0;
				break;
			}
		}

		if (found){
			if (round_key_dec[4 * AES128_NB_ROUND + 0] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 0] ^ setup_mix_big_endian(round_key_enc[4 * AES128_NB_ROUND - 1]) ^ rcon_big_endian[9])){
				continue;
			}
			if (round_key_dec[4 * AES128_NB_ROUND + 1] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 1] ^ round_key_dec[4 * AES128_NB_ROUND + 0])){
				continue;
			}
			if (round_key_dec[4 * AES128_NB_ROUND + 2] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 2] ^ round_key_dec[4 * AES128_NB_ROUND + 1])){
				continue;
			}
			if (round_key_dec[4 * AES128_NB_ROUND + 3] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 3] ^ round_key_dec[4 * AES128_NB_ROUND + 2])){
				continue;
			}

			sprintBuffer_raw_inv_endian(key_str, chunk->buffer + i, AES128_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES128", "b", "dec", chunk->offset + i, key_str);
		}
	}

	return;
}

void search_AES128_enc_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key;
	uint32_t 	tmp;
	uint8_t 	found;
	char 		key_str[2*AES128_KEY_NB_BYTE + 1];

	if (chunk->length < AES128_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES128_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key = (uint32_t*)(chunk->buffer + i);
		found = 1;

		for (j = 0; j < AES128_NB_ROUND; j++){
			tmp = round_key[4 * (j + 1) - 1];
			if (round_key[4 * (j + 1) + 0] != (round_key[4 * j + 0] ^ setup_mix_little_endian(tmp) ^ rcon_little_endian[j])){
				found = 0;
				break;
			}
			if (round_key[4 * (j + 1) + 1] != (round_key[4 * j + 1] ^ round_key[4 * (j + 1) + 0])){
				found = 0;
				break;
			}
			if (round_key[4 * (j + 1) + 2] != (round_key[4 * j + 2] ^ round_key[4 * (j + 1) + 1])){
				found = 0;
				break;
			}
			if (round_key[4 * (j + 1) + 3] != (round_key[4 * j + 3] ^ round_key[4 * (j + 1) + 2])){
				found = 0;
				break;
			}
		}

		if (found){
			sprintBuffer_raw(key_str, chunk->buffer + i, AES128_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES128", "l", "enc", chunk->offset + i, key_str);
		}
	}

	return;
}

void search_AES128_dec_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key_dec;
	uint32_t 	round_key_enc[AES128_ROUND_KEY_NB_WORD - 4];
	uint8_t 	found;
	char 		key_str[2*AES128_KEY_NB_BYTE + 1];

	if (chunk->length < AES128_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES128_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key_dec = (uint32_t*)(chunk->buffer + i);
		
		/* FORWARD */
		found = 1;

		round_key_enc[0] = round_key_dec[0];
		round_key_enc[1] = round_key_dec[1];
		round_key_enc[2] = round_key_dec[2];
		round_key_enc[3] = round_key_dec[3];

		for (j = 0; j < AES128_NB_ROUND - 1; j++){
			round_key_enc[4 * (j + 1) + 0] = round_key_enc[4 * j + 0] ^ setup_mix_little_endian(round_key_enc[4 * (j + 1) - 1]) ^ rcon_little_endian[j];
			if (mix_column_little_endian(round_key_dec[4 * (j + 1) + 0]) != round_key_enc[4 * (j + 1) + 0]){
				found = 0;
				break;
			}
			round_key_enc[4 * (j + 1) + 1] = round_key_enc[4 * j + 1] ^ round_key_enc[4 * (j + 1) + 0];
			if (mix_column_little_endian(round_key_dec[4 * (j + 1) + 1]) != round_key_enc[4 * (j + 1) + 1]){
				found = 0;
				break;
			}
			round_key_enc[4 * (j + 1) + 2] = round_key_enc[4 * j + 2] ^ round_key_enc[4 * (j + 1) + 1];
			if (mix_column_little_endian(round_key_dec[4 * (j + 1) + 2]) != round_key_enc[4 * (j + 1) + 2]){
				found = 0;
				break;
			}
			round_key_enc[4 * (j + 1) + 3] = round_key_enc[4 * j + 3] ^ round_key_enc[4 * (j + 1) + 2];
			if (mix_column_little_endian(round_key_dec[4 * (j + 1) + 3]) != round_key_enc[4 * (j + 1) + 3]){
				found = 0;
				break;
			}
		}

		if (found){
			if (round_key_dec[4 * AES128_NB_ROUND + 0] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 0] ^ setup_mix_little_endian(round_key_enc[4 * AES128_NB_ROUND - 1]) ^ rcon_little_endian[9])){
				continue;
			}
			if (round_key_dec[4 * AES128_NB_ROUND + 1] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 1] ^ round_key_dec[4 * AES128_NB_ROUND + 0])){
				continue;
			}
			if (round_key_dec[4 * AES128_NB_ROUND + 2] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 2] ^ round_key_dec[4 * AES128_NB_ROUND + 1])){
				continue;
			}
			if (round_key_dec[4 * AES128_NB_ROUND + 3] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 3] ^ round_key_dec[4 * AES128_NB_ROUND + 2])){
				continue;
			}

			sprintBuffer_raw(key_str, (char*)round_key_enc, AES128_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES128", "l", "dec", chunk->offset + i, key_str);
		}

		/* BACKWARD */
		found = 1;

		round_key_enc[0] = round_key_dec[4 * AES128_NB_ROUND + 0];
		round_key_enc[1] = round_key_dec[4 * AES128_NB_ROUND + 1];
		round_key_enc[2] = round_key_dec[4 * AES128_NB_ROUND + 2];
		round_key_enc[3] = round_key_dec[4 * AES128_NB_ROUND + 3];

		for (j = 0; j < AES128_NB_ROUND - 1; j++){
			round_key_enc[4 * (j + 1) + 0] = round_key_enc[4 * j + 0] ^ setup_mix_little_endian(round_key_enc[4 * (j + 1) - 1]) ^ rcon_little_endian[j];
			if (mix_column_little_endian(round_key_dec[4 * (AES128_NB_ROUND - (j + 1)) + 0]) != round_key_enc[4 * (j + 1) + 0]){
				found = 0;
				break;
			}
			round_key_enc[4 * (j + 1) + 1] = round_key_enc[4 * j + 1] ^ round_key_enc[4 * (j + 1) + 0];
			if (mix_column_little_endian(round_key_dec[4 * (AES128_NB_ROUND - (j + 1)) + 1]) != round_key_enc[4 * (j + 1) + 1]){
				found = 0;
				break;
			}
			round_key_enc[4 * (j + 1) + 2] = round_key_enc[4 * j + 2] ^ round_key_enc[4 * (j + 1) + 1];
			if (mix_column_little_endian(round_key_dec[4 * (AES128_NB_ROUND - (j + 1)) + 2]) != round_key_enc[4 * (j + 1) + 2]){
				found = 0;
				break;
			}
			round_key_enc[4 * (j + 1) + 3] = round_key_enc[4 * j + 3] ^ round_key_enc[4 * (j + 1) + 2];
			if (mix_column_little_endian(round_key_dec[4 * (AES128_NB_ROUND - (j + 1)) + 3]) != round_key_enc[4 * (j + 1) + 3]){
				found = 0;
				break;
			}
		}

		if (found){
			if (round_key_dec[0] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 0] ^ setup_mix_little_endian(round_key_enc[4 * AES128_NB_ROUND - 1]) ^ rcon_little_endian[9])){
				continue;
			}
			if (round_key_dec[1] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 1] ^ round_key_dec[0])){
				continue;
			}
			if (round_key_dec[2] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 2] ^ round_key_dec[1])){
				continue;
			}
			if (round_key_dec[3] != (round_key_enc[4 * (AES128_NB_ROUND - 1) + 3] ^ round_key_dec[2])){
				continue;
			}

			sprintBuffer_raw(key_str, (char*)round_key_enc, AES128_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES128", "l", "dec", chunk->offset + i, key_str);
		}
	}

	return;
}

void search_AES192_enc_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key;
	uint32_t 	tmp;
	uint8_t 	found;
	char 		key_str[2*AES192_KEY_NB_BYTE + 1];

	if (chunk->length < AES192_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES192_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key = (uint32_t*)(chunk->buffer + i);
		found = 1;
	
		for (j = 0; ; j++){
			tmp = round_key[6 * (j + 1) - 1];
			if (round_key[6 * (j + 1) + 0] != (round_key[6 * j + 0] ^ setup_mix_big_endian(tmp) ^ rcon_big_endian[j])){
				found = 0;
				break;
			}
			if (round_key[6 * (j + 1) + 1] != (round_key[6 * j + 1] ^ round_key[6 * (j + 1) + 0])){
				found = 0;
				break;
			}
			if (round_key[6 * (j + 1) + 2] != (round_key[6 * j + 2] ^ round_key[6 * (j + 1) + 1])){
				found = 0;
				break;
			}
			if (round_key[6 * (j + 1) + 3] != (round_key[6 * j + 3] ^ round_key[6 * (j + 1) + 2])){
				found = 0;
				break;
			}
			if (j == 7){
				break;
			}
			if (round_key[6 * (j + 1) + 4] != (round_key[6 * j + 4] ^ round_key[6 * (j + 1) + 3])){
				found = 0;
				break;
			}
			if (round_key[6 * (j + 1) + 5] != (round_key[6 * j + 5] ^ round_key[6 * (j + 1) + 4])){
				found = 0;
				break;
			}
		}

		if (found){
			sprintBuffer_raw_inv_endian(key_str, chunk->buffer + i, AES192_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES192", "b", "enc", chunk->offset + i, key_str);
		}
	}

	return;
}

void search_AES192_dec_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key_dec;
	uint32_t 	round_key_enc[AES192_ROUND_KEY_NB_WORD - 4];
	uint8_t 	found;
	char 		key_str[2*AES192_KEY_NB_BYTE + 1];

	if (chunk->length < AES192_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES192_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key_dec = (uint32_t*)(chunk->buffer + i);
		found = 1;

		round_key_enc[0] = round_key_dec[0];
		round_key_enc[1] = round_key_dec[1];
		round_key_enc[2] = round_key_dec[2];
		round_key_enc[3] = round_key_dec[3];

		round_key_enc[4] = mix_column_big_endian(round_key_dec[4]);
		round_key_enc[5] = mix_column_big_endian(round_key_dec[5]);

		for (j = 0; j < 7; j++){
			round_key_enc[6 * (j + 1) + 0] = round_key_enc[6 * j + 0] ^ setup_mix_big_endian(round_key_enc[6 * (j + 1) - 1]) ^ rcon_big_endian[j];
			if (mix_column_big_endian(round_key_dec[6 * (j + 1) + 0]) != round_key_enc[6 * (j + 1) + 0]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 1] = round_key_enc[6 * j + 1] ^ round_key_enc[6 * (j + 1) + 0];
			if (mix_column_big_endian(round_key_dec[6 * (j + 1) + 1]) != round_key_enc[6 * (j + 1) + 1]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 2] = round_key_enc[6 * j + 2] ^ round_key_enc[6 * (j + 1) + 1];
			if (mix_column_big_endian(round_key_dec[6 * (j + 1) + 2]) != round_key_enc[6 * (j + 1) + 2]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 3] = round_key_enc[6 * j + 3] ^ round_key_enc[6 * (j + 1) + 2];
			if (mix_column_big_endian(round_key_dec[6 * (j + 1) + 3]) != round_key_enc[6 * (j + 1) + 3]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 4] = round_key_enc[6 * j + 4] ^ round_key_enc[6 * (j + 1) + 3];
			if (mix_column_big_endian(round_key_dec[6 * (j + 1) + 4]) != round_key_enc[6 * (j + 1) + 4]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 5] = round_key_enc[6 * j + 5] ^ round_key_enc[6 * (j + 1) + 4];
			if (mix_column_big_endian(round_key_dec[6 * (j + 1) + 5]) != round_key_enc[6 * (j + 1) + 5]){
				found = 0;
				break;
			}
		}

		if (found){
			if (round_key_dec[4 * AES192_NB_ROUND + 0] != (round_key_enc[42] ^ setup_mix_big_endian(round_key_enc[47]) ^ rcon_big_endian[7])){
				continue;
			}
			if (round_key_dec[4 * AES192_NB_ROUND + 1] != (round_key_enc[43] ^ round_key_dec[48])){
				continue;
			}
			if (round_key_dec[4 * AES192_NB_ROUND + 2] != (round_key_enc[44] ^ round_key_dec[49])){
				continue;
			}
			if (round_key_dec[4 * AES192_NB_ROUND + 3] != (round_key_enc[45] ^ round_key_dec[50])){
				continue;
			}

			sprintBuffer_raw_inv_endian(key_str, (char*)round_key_enc, AES192_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES192", "b", "dec", chunk->offset + i, key_str);
		}
	}

	return;
}

void search_AES192_enc_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key;
	uint32_t 	tmp;
	uint8_t 	found;
	char 		key_str[2*AES192_KEY_NB_BYTE + 1];

	if (chunk->length < AES192_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES192_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key = (uint32_t*)(chunk->buffer + i);
		found = 1;
	
		for (j = 0; ; j++){
			tmp = round_key[6 * (j + 1) - 1];
			if (round_key[6 * (j + 1) + 0] != (round_key[6 * j + 0] ^ setup_mix_little_endian(tmp) ^ rcon_little_endian[j])){
				found = 0;
				break;
			}
			if (round_key[6 * (j + 1) + 1] != (round_key[6 * j + 1] ^ round_key[6 * (j + 1) + 0])){
				found = 0;
				break;
			}
			if (round_key[6 * (j + 1) + 2] != (round_key[6 * j + 2] ^ round_key[6 * (j + 1) + 1])){
				found = 0;
				break;
			}
			if (round_key[6 * (j + 1) + 3] != (round_key[6 * j + 3] ^ round_key[6 * (j + 1) + 2])){
				found = 0;
				break;
			}
			if (j == 7){
				break;
			}
			if (round_key[6 * (j + 1) + 4] != (round_key[6 * j + 4] ^ round_key[6 * (j + 1) + 3])){
				found = 0;
				break;
			}
			if (round_key[6 * (j + 1) + 5] != (round_key[6 * j + 5] ^ round_key[6 * (j + 1) + 4])){
				found = 0;
				break;
			}
		}

		if (found){
			sprintBuffer_raw(key_str, chunk->buffer + i, AES192_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES192", "l", "enc", chunk->offset + i, key_str);
		}
	}

	return;
}

void search_AES192_dec_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key_dec;
	uint32_t 	round_key_enc[AES192_ROUND_KEY_NB_WORD - 4];
	uint8_t 	found;
	char 		key_str[2*AES192_KEY_NB_BYTE + 1];

	if (chunk->length < AES192_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES192_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key_dec = (uint32_t*)(chunk->buffer + i);
		
		/* FORWARD */
		found = 1;

		round_key_enc[0] = round_key_dec[0];
		round_key_enc[1] = round_key_dec[1];
		round_key_enc[2] = round_key_dec[2];
		round_key_enc[3] = round_key_dec[3];

		round_key_enc[4] = mix_column_little_endian(round_key_dec[4]);
		round_key_enc[5] = mix_column_little_endian(round_key_dec[5]);

		for (j = 0; j < 7; j++){
			round_key_enc[6 * (j + 1) + 0] = round_key_enc[6 * j + 0] ^ setup_mix_little_endian(round_key_enc[6 * (j + 1) - 1]) ^ rcon_little_endian[j];
			if (mix_column_little_endian(round_key_dec[6 * (j + 1) + 0]) != round_key_enc[6 * (j + 1) + 0]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 1] = round_key_enc[6 * j + 1] ^ round_key_enc[6 * (j + 1) + 0];
			if (mix_column_little_endian(round_key_dec[6 * (j + 1) + 1]) != round_key_enc[6 * (j + 1) + 1]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 2] = round_key_enc[6 * j + 2] ^ round_key_enc[6 * (j + 1) + 1];
			if (mix_column_little_endian(round_key_dec[6 * (j + 1) + 2]) != round_key_enc[6 * (j + 1) + 2]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 3] = round_key_enc[6 * j + 3] ^ round_key_enc[6 * (j + 1) + 2];
			if (mix_column_little_endian(round_key_dec[6 * (j + 1) + 3]) != round_key_enc[6 * (j + 1) + 3]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 4] = round_key_enc[6 * j + 4] ^ round_key_enc[6 * (j + 1) + 3];
			if (mix_column_little_endian(round_key_dec[6 * (j + 1) + 4]) != round_key_enc[6 * (j + 1) + 4]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 5] = round_key_enc[6 * j + 5] ^ round_key_enc[6 * (j + 1) + 4];
			if (mix_column_little_endian(round_key_dec[6 * (j + 1) + 5]) != round_key_enc[6 * (j + 1) + 5]){
				found = 0;
				break;
			}
		}

		if (found){
			if (round_key_dec[4 * AES192_NB_ROUND + 0] != (round_key_enc[42] ^ setup_mix_little_endian(round_key_enc[47]) ^ rcon_little_endian[7])){
				continue;
			}
			if (round_key_dec[4 * AES192_NB_ROUND + 1] != (round_key_enc[43] ^ round_key_dec[48])){
				continue;
			}
			if (round_key_dec[4 * AES192_NB_ROUND + 2] != (round_key_enc[44] ^ round_key_dec[49])){
				continue;
			}
			if (round_key_dec[4 * AES192_NB_ROUND + 3] != (round_key_enc[45] ^ round_key_dec[50])){
				continue;
			}

			sprintBuffer_raw(key_str, (char*)round_key_enc, AES192_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES192", "l", "dec", chunk->offset + i, key_str);
		}

		/* BACKWARD */
		found = 1;

		round_key_enc[0] = round_key_dec[4 * AES192_NB_ROUND + 0];
		round_key_enc[1] = round_key_dec[4 * AES192_NB_ROUND + 1];
		round_key_enc[2] = round_key_dec[4 * AES192_NB_ROUND + 2];
		round_key_enc[3] = round_key_dec[4 * AES192_NB_ROUND + 3];

		round_key_enc[4] = mix_column_little_endian(round_key_dec[4 * (AES192_NB_ROUND - 1) + 0]);
		round_key_enc[5] = mix_column_little_endian(round_key_dec[4 * (AES192_NB_ROUND - 1) + 1]);

		for (j = 0; j < 7; j++){
			round_key_enc[6 * (j + 1) + 0] = round_key_enc[6 * j + 0] ^ setup_mix_little_endian(round_key_enc[6 * (j + 1) - 1]) ^ rcon_little_endian[j];
			if (mix_column_little_endian(round_key_dec[6 * (7 - j) + ((6 * (7 - j)) % 4) * 2]) != round_key_enc[6 * (j + 1) + 0]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 1] = round_key_enc[6 * j + 1] ^ round_key_enc[6 * (j + 1) + 0];
			if (mix_column_little_endian(round_key_dec[6 * (7 - j) + ((6 * (7 - j)) % 4) * 2 + 1]) != round_key_enc[6 * (j + 1) + 1]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 2] = round_key_enc[6 * j + 2] ^ round_key_enc[6 * (j + 1) + 1];
			if (mix_column_little_endian(round_key_dec[6 * (7 - j) + 2 - ((6 * (7 - j)) % 4) * 2]) != round_key_enc[6 * (j + 1) + 2]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 3] = round_key_enc[6 * j + 3] ^ round_key_enc[6 * (j + 1) + 2];
			if (mix_column_little_endian(round_key_dec[6 * (7 - j) + 3 - ((6 * (7 - j)) % 4) * 2]) != round_key_enc[6 * (j + 1) + 3]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 4] = round_key_enc[6 * j + 4] ^ round_key_enc[6 * (j + 1) + 3];
			if (mix_column_little_endian(round_key_dec[6 * (7 - j) - 4 + ((6 * (7 - j)) % 4) * 2]) != round_key_enc[6 * (j + 1) + 4]){
				found = 0;
				break;
			}
			round_key_enc[6 * (j + 1) + 5] = round_key_enc[6 * j + 5] ^ round_key_enc[6 * (j + 1) + 4];
			if (mix_column_little_endian(round_key_dec[6 * (7 - j) - 3 + ((6 * (7 - j)) % 4) * 2]) != round_key_enc[6 * (j + 1) + 5]){
				found = 0;
				break;
			}
		}

		if (found){
			if (round_key_dec[0] != (round_key_enc[42] ^ setup_mix_little_endian(round_key_enc[47]) ^ rcon_little_endian[7])){
				continue;
			}
			if (round_key_dec[1] != (round_key_enc[43] ^ round_key_dec[0])){
				continue;
			}
			if (round_key_dec[2] != (round_key_enc[44] ^ round_key_dec[1])){
				continue;
			}
			if (round_key_dec[3] != (round_key_enc[45] ^ round_key_dec[2])){
				continue;
			}

			sprintBuffer_raw(key_str, (char*)round_key_enc, AES192_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES192", "l", "dec", chunk->offset + i, key_str);
		}
	}

	return;
}

void search_AES256_enc_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key;
	uint32_t 	tmp;
	uint8_t 	found;
	char 		key_str[2*AES256_KEY_NB_BYTE + 1];

	if (chunk->length < AES192_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES192_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key = (uint32_t*)(chunk->buffer + i);
		found = 1;

		for (j = 0; ; j++){
			tmp = round_key[8 * (j + 1) - 1];
			if (round_key[8 * (j + 1) + 0] != (round_key[8 * j + 0] ^ setup_mix_big_endian(tmp) ^ rcon_big_endian[j])){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 1] != (round_key[8 * j + 1] ^ round_key[8 * (j + 1) + 0])){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 2] != (round_key[8 * j + 2] ^ round_key[8 * (j + 1) + 1])){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 3] != (round_key[8 * j + 3] ^ round_key[8 * (j + 1) + 2])){
				found = 0;
				break;
			}
			if (j == 6){
				break;
			}
			tmp = round_key[8 * (j + 1) + 3];
			if (round_key[8 * (j + 1) + 4] != (round_key[8 * j + 4] ^ setup_mix_big_endian(RORc_big_endian(tmp, 8)))){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 5] != (round_key[8 * j + 5] ^ round_key[8 * (j + 1) + 4])){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 6] != (round_key[8 * j + 6] ^ round_key[8 * (j + 1) + 5])){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 7] != (round_key[8 * j + 7] ^ round_key[8 * (j + 1) + 6])){
				found = 0;
				break;
			}
		}

		if (found){
			sprintBuffer_raw_inv_endian(key_str, chunk->buffer + i, AES256_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES256", "b", "enc", chunk->offset + i, key_str);
		}
	}

	return;
}

void search_AES256_dec_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key_dec;
	uint32_t 	round_key_enc[AES256_ROUND_KEY_NB_WORD - 4];
	uint8_t 	found;
	char 		key_str[2*AES256_KEY_NB_BYTE + 1];

	if (chunk->length < AES256_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES256_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key_dec = (uint32_t*)(chunk->buffer + i);
		found = 1;

		round_key_enc[0] = round_key_dec[0];
		round_key_enc[1] = round_key_dec[1];
		round_key_enc[2] = round_key_dec[2];
		round_key_enc[3] = round_key_dec[3];

		round_key_enc[4] = mix_column_big_endian(round_key_dec[4]);
		round_key_enc[5] = mix_column_big_endian(round_key_dec[5]);
		round_key_enc[6] = mix_column_big_endian(round_key_dec[6]);
		round_key_enc[7] = mix_column_big_endian(round_key_dec[7]);

		for (j = 0; j < 6; j++){
			round_key_enc[8 * (j + 1) + 0] = round_key_enc[8 * j + 0] ^ setup_mix_big_endian(round_key_enc[8 * (j + 1) - 1]) ^ rcon_big_endian[j];
			if (mix_column_big_endian(round_key_dec[8 * (j + 1) + 0]) != round_key_enc[8 * (j + 1) + 0]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 1] = round_key_enc[8 * j + 1] ^ round_key_enc[8 * (j + 1) + 0];
			if (mix_column_big_endian(round_key_dec[8 * (j + 1) + 1]) != round_key_enc[8 * (j + 1) + 1]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 2] = round_key_enc[8 * j + 2] ^ round_key_enc[8 * (j + 1) + 1];
			if (mix_column_big_endian(round_key_dec[8 * (j + 1) + 2]) != round_key_enc[8 * (j + 1) + 2]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 3] = round_key_enc[8 * j + 3] ^ round_key_enc[8 * (j + 1) + 2];
			if (mix_column_big_endian(round_key_dec[8 * (j + 1) + 3]) != round_key_enc[8 * (j + 1) + 3]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 4] = round_key_enc[8 * j + 4] ^ setup_mix_big_endian(RORc_big_endian(round_key_enc[8 * (j + 1) + 3], 8));
			if (mix_column_big_endian(round_key_dec[8 * (j + 1) + 4]) != round_key_enc[8 * (j + 1) + 4]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 5] = round_key_enc[8 * j + 5] ^ round_key_enc[8 * (j + 1) + 4];
			if (mix_column_big_endian(round_key_dec[8 * (j + 1) + 5]) != round_key_enc[8 * (j + 1) + 5]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 6] = round_key_enc[8 * j + 6] ^ round_key_enc[8 * (j + 1) + 5];
			if (mix_column_big_endian(round_key_dec[8 * (j + 1) + 6]) != round_key_enc[8 * (j + 1) + 6]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 7] = round_key_enc[8 * j + 7] ^ round_key_enc[8 * (j + 1) + 6];
			if (mix_column_big_endian(round_key_dec[8 * (j + 1) + 7]) != round_key_enc[8 * (j + 1) + 7]){
				found = 0;
				break;
			}
		}

		if (found){
			if (round_key_dec[4 * AES256_NB_ROUND + 0] != (round_key_enc[48] ^ setup_mix_big_endian(round_key_enc[55]) ^ rcon_big_endian[6])){
				continue;
			}
			if (round_key_dec[4 * AES256_NB_ROUND + 1] != (round_key_enc[49] ^ round_key_dec[56])){
				continue;
			}
			if (round_key_dec[4 * AES256_NB_ROUND + 2] != (round_key_enc[50] ^ round_key_dec[57])){
				continue;
			}
			if (round_key_dec[4 * AES256_NB_ROUND + 3] != (round_key_enc[51] ^ round_key_dec[58])){
				continue;
			}

			sprintBuffer_raw_inv_endian(key_str, (char*)round_key_enc, AES256_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES256", "b", "dec", chunk->offset + i, key_str);
		}
	}

	return;
}

void search_AES256_enc_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key;
	uint32_t 	tmp;
	uint8_t 	found;
	char 		key_str[2*AES256_KEY_NB_BYTE + 1];

	if (chunk->length < AES192_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES192_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key = (uint32_t*)(chunk->buffer + i);
		found = 1;

		for (j = 0; ; j++){
			tmp = round_key[8 * (j + 1) - 1];
			if (round_key[8 * (j + 1) + 0] != (round_key[8 * j + 0] ^ setup_mix_little_endian(tmp) ^ rcon_little_endian[j])){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 1] != (round_key[8 * j + 1] ^ round_key[8 * (j + 1) + 0])){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 2] != (round_key[8 * j + 2] ^ round_key[8 * (j + 1) + 1])){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 3] != (round_key[8 * j + 3] ^ round_key[8 * (j + 1) + 2])){
				found = 0;
				break;
			}
			if (j == 6){
				break;
			}
			tmp = round_key[8 * (j + 1) + 3];
			if (round_key[8 * (j + 1) + 4] != (round_key[8 * j + 4] ^ setup_mix_little_endian(RORc_little_endian(tmp, 8)))){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 5] != (round_key[8 * j + 5] ^ round_key[8 * (j + 1) + 4])){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 6] != (round_key[8 * j + 6] ^ round_key[8 * (j + 1) + 5])){
				found = 0;
				break;
			}
			if (round_key[8 * (j + 1) + 7] != (round_key[8 * j + 7] ^ round_key[8 * (j + 1) + 6])){
				found = 0;
				break;
			}
		}

		if (found){
			sprintBuffer_raw(key_str, chunk->buffer + i, AES256_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES256", "l", "enc", chunk->offset + i, key_str);
		}
	}

	return;
}

void search_AES256_dec_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	round_key_dec;
	uint32_t 	round_key_enc[AES256_ROUND_KEY_NB_WORD - 4];
	uint8_t 	found;
	char 		key_str[2*AES256_KEY_NB_BYTE + 1];

	if (chunk->length < AES256_ROUND_KEY_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - AES256_ROUND_KEY_NB_BYTE + 1; i += STEP_NB_BYTE){
		round_key_dec = (uint32_t*)(chunk->buffer + i);
		
		/* FORWARD */
		found = 1;

		round_key_enc[0] = round_key_dec[0];
		round_key_enc[1] = round_key_dec[1];
		round_key_enc[2] = round_key_dec[2];
		round_key_enc[3] = round_key_dec[3];

		round_key_enc[4] = mix_column_little_endian(round_key_dec[4]);
		round_key_enc[5] = mix_column_little_endian(round_key_dec[5]);
		round_key_enc[6] = mix_column_little_endian(round_key_dec[6]);
		round_key_enc[7] = mix_column_little_endian(round_key_dec[7]);

		for (j = 0; j < 6; j++){
			round_key_enc[8 * (j + 1) + 0] = round_key_enc[8 * j + 0] ^ setup_mix_little_endian(round_key_enc[8 * (j + 1) - 1]) ^ rcon_little_endian[j];
			if (mix_column_little_endian(round_key_dec[8 * (j + 1) + 0]) != round_key_enc[8 * (j + 1) + 0]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 1] = round_key_enc[8 * j + 1] ^ round_key_enc[8 * (j + 1) + 0];
			if (mix_column_little_endian(round_key_dec[8 * (j + 1) + 1]) != round_key_enc[8 * (j + 1) + 1]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 2] = round_key_enc[8 * j + 2] ^ round_key_enc[8 * (j + 1) + 1];
			if (mix_column_little_endian(round_key_dec[8 * (j + 1) + 2]) != round_key_enc[8 * (j + 1) + 2]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 3] = round_key_enc[8 * j + 3] ^ round_key_enc[8 * (j + 1) + 2];
			if (mix_column_little_endian(round_key_dec[8 * (j + 1) + 3]) != round_key_enc[8 * (j + 1) + 3]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 4] = round_key_enc[8 * j + 4] ^ setup_mix_little_endian(RORc_little_endian(round_key_enc[8 * (j + 1) + 3], 8));
			if (mix_column_little_endian(round_key_dec[8 * (j + 1) + 4]) != round_key_enc[8 * (j + 1) + 4]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 5] = round_key_enc[8 * j + 5] ^ round_key_enc[8 * (j + 1) + 4];
			if (mix_column_little_endian(round_key_dec[8 * (j + 1) + 5]) != round_key_enc[8 * (j + 1) + 5]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 6] = round_key_enc[8 * j + 6] ^ round_key_enc[8 * (j + 1) + 5];
			if (mix_column_little_endian(round_key_dec[8 * (j + 1) + 6]) != round_key_enc[8 * (j + 1) + 6]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 7] = round_key_enc[8 * j + 7] ^ round_key_enc[8 * (j + 1) + 6];
			if (mix_column_little_endian(round_key_dec[8 * (j + 1) + 7]) != round_key_enc[8 * (j + 1) + 7]){
				found = 0;
				break;
			}
		}

		if (found){
			if (round_key_dec[4 * AES256_NB_ROUND + 0] != (round_key_enc[48] ^ setup_mix_little_endian(round_key_enc[55]) ^ rcon_little_endian[6])){
				continue;
			}
			if (round_key_dec[4 * AES256_NB_ROUND + 1] != (round_key_enc[49] ^ round_key_dec[56])){
				continue;
			}
			if (round_key_dec[4 * AES256_NB_ROUND + 2] != (round_key_enc[50] ^ round_key_dec[57])){
				continue;
			}
			if (round_key_dec[4 * AES256_NB_ROUND + 3] != (round_key_enc[51] ^ round_key_dec[58])){
				continue;
			}

			sprintBuffer_raw(key_str, (char*)round_key_enc, AES256_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES256", "l", "dec", chunk->offset + i, key_str);
		}

		/* BACKWARD */
		found = 1;

		round_key_enc[0] = round_key_dec[4 * AES256_NB_ROUND + 0];
		round_key_enc[1] = round_key_dec[4 * AES256_NB_ROUND + 1];
		round_key_enc[2] = round_key_dec[4 * AES256_NB_ROUND + 2];
		round_key_enc[3] = round_key_dec[4 * AES256_NB_ROUND + 3];

		round_key_enc[4] = mix_column_little_endian(round_key_dec[4 * (AES256_NB_ROUND - 1) + 0]);
		round_key_enc[5] = mix_column_little_endian(round_key_dec[4 * (AES256_NB_ROUND - 1) + 1]);
		round_key_enc[6] = mix_column_little_endian(round_key_dec[4 * (AES256_NB_ROUND - 1) + 2]);
		round_key_enc[7] = mix_column_little_endian(round_key_dec[4 * (AES256_NB_ROUND - 1) + 3]);

		for (j = 0; j < 6; j++){
			round_key_enc[8 * (j + 1) + 0] = round_key_enc[8 * j + 0] ^ setup_mix_little_endian(round_key_enc[8 * (j + 1) - 1]) ^ rcon_little_endian[j];
			if (mix_column_little_endian(round_key_dec[8 * (6 - j) + 0]) != round_key_enc[8 * (j + 1) + 0]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 1] = round_key_enc[8 * j + 1] ^ round_key_enc[8 * (j + 1) + 0];
			if (mix_column_little_endian(round_key_dec[8 * (6 - j) + 1]) != round_key_enc[8 * (j + 1) + 1]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 2] = round_key_enc[8 * j + 2] ^ round_key_enc[8 * (j + 1) + 1];
			if (mix_column_little_endian(round_key_dec[8 * (6 - j) + 2]) != round_key_enc[8 * (j + 1) + 2]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 3] = round_key_enc[8 * j + 3] ^ round_key_enc[8 * (j + 1) + 2];
			if (mix_column_little_endian(round_key_dec[8 * (6 - j) + 3]) != round_key_enc[8 * (j + 1) + 3]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 4] = round_key_enc[8 * j + 4] ^ setup_mix_little_endian(RORc_little_endian(round_key_enc[8 * (j + 1) + 3], 8));
			if (mix_column_little_endian(round_key_dec[8 * (6 - j) - 4]) != round_key_enc[8 * (j + 1) + 4]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 5] = round_key_enc[8 * j + 5] ^ round_key_enc[8 * (j + 1) + 4];
			if (mix_column_little_endian(round_key_dec[8 * (6 - j) - 3]) != round_key_enc[8 * (j + 1) + 5]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 6] = round_key_enc[8 * j + 6] ^ round_key_enc[8 * (j + 1) + 5];
			if (mix_column_little_endian(round_key_dec[8 * (6 - j) - 2]) != round_key_enc[8 * (j + 1) + 6]){
				found = 0;
				break;
			}
			round_key_enc[8 * (j + 1) + 7] = round_key_enc[8 * j + 7] ^ round_key_enc[8 * (j + 1) + 6];
			if (mix_column_little_endian(round_key_dec[8 * (6 - j) - 1]) != round_key_enc[8 * (j + 1) + 7]){
				found = 0;
				break;
			}
		}

		if (found){
			if (round_key_dec[0] != (round_key_enc[48] ^ setup_mix_little_endian(round_key_enc[55]) ^ rcon_little_endian[6])){
				continue;
			}
			if (round_key_dec[1] != (round_key_enc[49] ^ round_key_dec[0])){
				continue;
			}
			if (round_key_dec[2] != (round_key_enc[50] ^ round_key_dec[1])){
				continue;
			}
			if (round_key_dec[3] != (round_key_enc[51] ^ round_key_dec[2])){
				continue;
			}

			sprintBuffer_raw(key_str, (char*)round_key_enc, AES256_KEY_NB_BYTE);
			multiColumnPrinter_print(printer, chunk->file_name, "AES256", "l", "dec", chunk->offset + i, key_str);
		}
	}

	return;
}