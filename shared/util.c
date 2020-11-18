#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "util.h"

int32_t fileChunk_open(struct fileChunk* chunk, const char* file_name){
	FILE* file;

	if ((file = fopen(file_name, "r")) == NULL){
		log_err_m("Unable to open file: \"%s\"", file_name);
		return -1;
	}

	fileChunk_init(*chunk, file, file_name)

	return 0;
}

size_t fileChunk_get_next(struct fileChunk* chunk){
	size_t size;

	if (chunk->buffer == NULL){
		chunk->size = 0;
		chunk->offset = 0;
		if ((chunk->buffer = malloc(FILECHUNCK_MAX_SIZE)) == NULL){
			log_err("Unable to allocate memory");
			return 0;
		}
	}
	else if (chunk->size > FILECHUNCK_OVERLAP){
		chunk->offset += chunk->size - FILECHUNCK_OVERLAP;
		memmove(chunk->buffer, chunk->buffer + chunk->size - FILECHUNCK_OVERLAP, FILECHUNCK_OVERLAP);
		chunk->size = FILECHUNCK_OVERLAP;
	}
	else {
		chunk->offset += chunk->size;
		chunk->size = 0;
		return 0;
	}

	do {
		size = fread(chunk->buffer + chunk->size, 1, FILECHUNCK_MAX_SIZE - chunk->size, chunk->file);
		chunk->size += size;
		if (!size){
			break;
		}
	} while (chunk->size != FILECHUNCK_MAX_SIZE);

	return chunk->size;
}

void inv_endian(char* buffer, size_t size){
	size_t i;

	if (size & 0x00000003){
		log_err_m("Size %zu is not a multiple of 4", size);
		return;
	}

	for (i = 0; i < (size >> 2); i++){
		*((uint32_t*)buffer + i) =__builtin_bswap32(*((uint32_t*)buffer + i));
	}
}

static const char hexa[16] = {'0', '1', '2', '3', '4' , '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

void fprintBuffer_raw(FILE* file, const char* buffer, size_t buffer_length){
	size_t i;

	for (i = 0; i < buffer_length; i++){
		fprintf(file, "%c%c", hexa[(buffer[i] >> 4) & 0x0f], hexa[buffer[i] & 0x0f]);
	}
}

void fprintBuffer_raw_inv_endian(FILE* file, const char* buffer, size_t buffer_length){
	size_t i;

	if (buffer_length % 4){
		log_err("Buffer length must be a multiple of 4");
		return;
	}

	for (i = 0; i < buffer_length; i ++){
		fprintf(file, "%c%c", hexa[(buffer[4*(i/4 + 1) - (i%4) - 1] >> 4) & 0x0f], hexa[buffer[4*(i/4 + 1) - (i%4) - 1] & 0x0f]);
	}
}

void sprintBuffer_raw(char* str, const char* buffer, size_t buffer_length){
	size_t 	i;
	int32_t pointer;

	if (buffer_length){
		for (i = 0; i < buffer_length; i++){
			pointer = sprintf(str, "%c%c", hexa[(buffer[i] >> 4) & 0x0f], hexa[buffer[i] & 0x0f]);
			if (pointer > 0){
				str += pointer;
			}
			else {
				log_err("snprintf returns an error code");
				break;
			}
		}
	}
	else {
		str[0] = 0;
	}
}

void sprintBuffer_raw_inv_endian(char* str, const char* buffer, size_t buffer_length){
	size_t 	i;
	int32_t pointer;

	if (buffer_length){
		if (buffer_length % 4){
			log_err("Buffer length must be a multiple of 4");
			return;
		}

		for (i = 0; i < buffer_length; i++){
			pointer = sprintf(str, "%c%c", hexa[(buffer[4*(i/4 + 1) - (i%4) - 1] >> 4) & 0x0f], hexa[buffer[4*(i/4 + 1) - (i%4) - 1] & 0x0f]);
			if (pointer > 0){
				str += pointer;
			}
			else {
				log_err("snprintf returns an error code");
				break;
			}
		}
	}
	else {
		str[0] = 0;
	}
}

static const uint8_t decoding_table[128] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255, 255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 255, 255, 255, 255, 255};

unsigned char* base64_decode(const char* data, size_t input_length, size_t *output_length){
	unsigned char* decoded_data;
	size_t i;
	size_t j;
	uint32_t tmp;

	if (input_length % 4){
		log_err_m("input length (%zu) is not a multiple of 4", input_length);
		return NULL;
	}

	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '='){
		(*output_length)--;
	}
	if (data[input_length - 2] == '='){
		(*output_length)--;
	}

	if ((decoded_data = malloc(*output_length)) == NULL){
		log_err("unable to allocate memory");
		return NULL;
	}

	for (i = 0, j = 0; i < input_length; i += 4){
		if (*(uint32_t*)(data + i) & 0x80808080){
			free(decoded_data);
			return NULL;
		}

		tmp = (data[i] == '=') ? 0 : decoding_table[(uint32_t)data[i]];
		tmp = (tmp << 6) + ((data[i + 1] == '=') ? 0 : decoding_table[(uint32_t)data[i + 1]]);
		tmp = (tmp << 6) + ((data[i + 2] == '=') ? 0 : decoding_table[(uint32_t)data[i + 2]]);
		tmp = (tmp << 6) + ((data[i + 3] == '=') ? 0 : decoding_table[(uint32_t)data[i + 3]]);

		if (j < *output_length){
			decoded_data[j++] = (tmp >> 16) & 0xFF;
			if (j < *output_length){
				decoded_data[j++] = (tmp >> 8) & 0xFF;
				if (j < *output_length){
					decoded_data[j++] = tmp & 0xFF;
				}
			}
		}
	}

	return decoded_data;
}
