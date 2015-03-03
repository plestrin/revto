#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "msg_sha.h"

#include "util.h"

#define SHA1_EXPAND_MSG_NB_BIT 		2560
#define SHA1_EXPAND_MSG_NB_BYTE 	320
#define SHA1_EXPAND_MSG_NB_WORD 	80

#define SHA1_MSG_NB_BIT 			512
#define SHA1_MSG_NB_BYTE 			64
#define SHA1_MSG_NB_WORD 			16

#define SHA256_EXPAND_MSG_NB_BIT 	2048
#define SHA256_EXPAND_MSG_NB_BYTE 	256
#define SHA256_EXPAND_MSG_NB_WORD 	64

#define SHA256_MSG_NB_BIT 			512
#define SHA256_MSG_NB_BYTE 			64
#define SHA256_MSG_NB_WORD 			16

#define SHA512_EXPAND_MSG_NB_BIT 	5120
#define SHA512_EXPAND_MSG_NB_BYTE 	640
#define SHA512_EXPAND_MSG_NB_WORD 	160
#define SHA512_EXPAND_MSG_NB_DWORD 	80

#define SHA512_MSG_NB_BIT 			1024
#define SHA512_MSG_NB_BYTE 			128
#define SHA512_MSG_NB_WORD 			32
#define SHA512_MSG_NB_DWORD 		16

#define ROL_32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR_32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROL_64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define ROR_64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define SHA1_NB_BLACK_LISTED_MSG 1

static const uint32_t black_listed_msg_sha1[SHA1_NB_BLACK_LISTED_MSG][SHA1_MSG_NB_WORD] = {
	{
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000
	}
};

#define SHA1_MSG_SCHEDULE_MIN 34
#define SHA1_MSG_SCHEDULE_MAX 80

void search_sha1_msg(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	msg_buffer;
	char 		msg_str[2*SHA1_MSG_NB_BYTE + 1];
	uint32_t 	last_found[4] = {0, 0, 0, 0};

	if (chunk->length < SHA1_EXPAND_MSG_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - SHA1_EXPAND_MSG_NB_BYTE + 1; i += STEP_NB_BYTE){
		msg_buffer = (uint32_t*)(chunk->buffer + i);

		for (j = 0; j < SHA1_NB_BLACK_LISTED_MSG; j++){
			if (memcmp(msg_buffer, black_listed_msg_sha1[j], SHA1_MSG_NB_BYTE) == 0){
				goto next;
			}
		}

		for(j = 16; j < SHA1_MSG_SCHEDULE_MAX; j++){
			if (msg_buffer[j] != ROL_32(msg_buffer[j - 3] ^ msg_buffer[j - 8] ^ msg_buffer[j - 14] ^ msg_buffer[j - 16], 1)){
				if (j < SHA1_MSG_SCHEDULE_MIN + last_found[i % 4]){
					goto next;
				}
				else{
					break;
				}
			}
		}

		last_found[i % 4] = (j + 1) - SHA1_MSG_SCHEDULE_MIN;

		sprintBuffer_raw_inv_endian(msg_str, (char*)msg_buffer, SHA1_MSG_NB_BYTE);
		if (j != SHA1_MSG_SCHEDULE_MAX){
			multiColumnPrinter_print(printer, chunk->file_name, "SHA1", "b", "~ <!>", chunk->offset + i, msg_str);
		}
		else{
			multiColumnPrinter_print(printer, chunk->file_name, "SHA1", "b", "msg", chunk->offset + i, msg_str);
		}

		next:;
		if (last_found[i % 4] > 0){
			last_found[i % 4] --;
		}
	}

	return;
}

#define Gamma0_32(x) 	(ROR_32(x, 7 ) ^ ROR_32(x, 18) ^ ((x) >> 3 ))
#define Gamma1_32(x) 	(ROR_32(x, 17) ^ ROR_32(x, 19) ^ ((x) >> 10))

#define SHA256_NB_BLACK_LISTED_MSG 1

static const uint32_t black_listed_msg_sha256[SHA256_NB_BLACK_LISTED_MSG][SHA256_MSG_NB_WORD] = {
	{
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000
	}
};

#define SHA256_MSG_SCHEDULE_MIN 36
#define SHA256_MSG_SCHEDULE_MAX 64

void search_sha256_msg(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	msg_buffer;
	char 		msg_str[2*SHA256_MSG_NB_BYTE + 1];
	uint32_t 	last_found[4] = {0, 0, 0, 0};

	if (chunk->length < SHA256_EXPAND_MSG_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - SHA256_EXPAND_MSG_NB_BYTE + 1; i += STEP_NB_BYTE){
		msg_buffer = (uint32_t*)(chunk->buffer + i);

		for (j = 0; j < SHA256_NB_BLACK_LISTED_MSG; j++){
			if (memcmp(msg_buffer, black_listed_msg_sha256[j], SHA256_MSG_NB_BYTE) == 0){
				goto next;
			}
		}

		for(j = 16; j < SHA256_MSG_SCHEDULE_MAX; j++){
			if (msg_buffer[j] !=  Gamma1_32(msg_buffer[j - 2]) + msg_buffer[j - 7] + Gamma0_32(msg_buffer[j - 15]) + msg_buffer[j - 16]){
				if (j < SHA256_MSG_SCHEDULE_MIN + last_found[i % 4]){
					goto next;
				}
				else{
					break;
				}
			}
		}
		
		last_found[i % 4] = (j + 1) - SHA256_MSG_SCHEDULE_MIN;

		sprintBuffer_raw_inv_endian(msg_str, (char*)msg_buffer, SHA256_MSG_NB_BYTE);
		if (j != SHA256_MSG_SCHEDULE_MAX){
			multiColumnPrinter_print(printer, chunk->file_name, "SHA256", "b", "~ <!>", chunk->offset + i, msg_str);
		}
		else{
			multiColumnPrinter_print(printer, chunk->file_name, "SHA256", "b", "msg", chunk->offset + i, msg_str);
		}

		next:;
		if (last_found[i % 4] > 0){
			last_found[i % 4] --;
		}
	}

	return;
}

#define Gamma0_64(x) 	(ROR_64(x, 1 ) ^ ROR_64(x, 8 ) ^ ((x) >> 7))
#define Gamma1_64(x) 	(ROR_64(x, 19) ^ ROR_64(x, 61) ^ ((x) >> 6))

#define SHA512_NB_BLACK_LISTED_MSG 1

static const uint64_t black_listed_msg_sha512[SHA512_NB_BLACK_LISTED_MSG][SHA512_MSG_NB_DWORD] = {
	{
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
	}
};

#define SHA512_MSG_SCHEDULE_MIN 36
#define SHA512_MSG_SCHEDULE_MAX 80

void search_sha512_msg(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint64_t* 	msg_buffer;
	char 		msg_str[2*SHA512_MSG_NB_BYTE + 1];
	uint32_t 	last_found[8] = {0, 0, 0, 0, 0, 0, 0, 0};

	if (chunk->length < SHA512_EXPAND_MSG_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - SHA512_EXPAND_MSG_NB_BYTE + 1; i += STEP_NB_BYTE){
		msg_buffer = (uint64_t*)(chunk->buffer + i);

		for (j = 0; j < SHA512_NB_BLACK_LISTED_MSG; j++){
			if (memcmp(msg_buffer, black_listed_msg_sha512[j], SHA512_MSG_NB_BYTE) == 0){
				goto next;
			}
		}

		for(j = 16; j < SHA512_MSG_SCHEDULE_MAX; j++){
			if (msg_buffer[j] !=  Gamma1_64(msg_buffer[j - 2]) + msg_buffer[j - 7] + Gamma0_64(msg_buffer[j - 15]) + msg_buffer[j - 16]){
				if (j < SHA512_MSG_SCHEDULE_MIN + last_found[i % 8]){
					goto next;
				}
				else{
					break;
				}
			}
		}
		
		last_found[i % 8] = (j + 1) - SHA512_MSG_SCHEDULE_MIN;

		sprintBuffer_raw_inv_endian(msg_str, (char*)msg_buffer, SHA512_MSG_NB_BYTE);
		if (j != SHA512_MSG_SCHEDULE_MAX){
			multiColumnPrinter_print(printer, chunk->file_name, "SHA512", "b", "~ <!>", chunk->offset + i, msg_str);
		}
		else{
			multiColumnPrinter_print(printer, chunk->file_name, "SHA512", "b", "msg", chunk->offset + i, msg_str);
		}

		next:;
		if (last_found[i % 8] > 0){
			last_found[i % 8] --;
		}
	}

	return;
}