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

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define SHA1_NB_BLACK_LISTED_MSG 1

static const uint32_t black_listed_msg[SHA1_NB_BLACK_LISTED_MSG][SHA1_MSG_NB_WORD] = {
	{
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000
	}
};

void search_sha1_msg(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	uint64_t 	i;
	uint32_t 	j;
	uint32_t* 	msg_buffer;
	char 		msg_str[2*SHA1_MSG_NB_BYTE + 1];

	if (chunk->length < SHA1_EXPAND_MSG_NB_BYTE){
		return;
	}

	for (i = 0; i < chunk->length - SHA1_EXPAND_MSG_NB_BYTE + 1; i += STEP_NB_BYTE){
		msg_buffer = (uint32_t*)(chunk->buffer + i);

		for (j = 0; j < SHA1_NB_BLACK_LISTED_MSG; j++){
			if (memcmp(msg_buffer, black_listed_msg[j], SHA1_MSG_NB_BYTE) == 0){
				goto next;
			}
		}

		for(j = 16; j < 80; j++){
			if (msg_buffer[j] != ROTATE_LEFT(msg_buffer[j - 3] ^ msg_buffer[j - 8] ^ msg_buffer[j - 14] ^ msg_buffer[j - 16], 1)){
				goto next;
			}
		}

		sprintBuffer_raw_inv_endian(msg_str, (char*)msg_buffer, SHA1_MSG_NB_BYTE);
		multiColumnPrinter_print(printer, chunk->file_name, "SHA1", "l", "msg", chunk->offset + i, msg_str);

		next:;
	}

	return;
}
