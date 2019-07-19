#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "key_pem.h"
#include "key_ber.h"

#include "searchCryptoKey.h"

#define PEM_MAX_LENGTH 4096

#define PEM_START_TAG "-----BEGIN RSA PRIVATE KEY-----"
#define PEM_START_TAG_LEN (sizeof PEM_START_TAG - 1)
#define PEM_STOP_TAG "-----END RSA PRIVATE KEY-----"
#define PEM_STOP_TAG_LEN (sizeof PEM_STOP_TAG - 1)

extern const struct ber_field_meta_print ber_frt_rsa_pri_key[];

void search_pem_key(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	size_t 				size;
	char* 				start;
	struct fileChunk 	sub_chunk;

	sub_chunk.file = NULL;
	sub_chunk.file_name = NULL;
	sub_chunk.buffer = NULL;
	sub_chunk.size = 0;
	sub_chunk.offset = 0;

	for (start = chunk->buffer, size = chunk->size; ; ){
		size_t 	i;
		size_t 	j;
		char* 	tmp;
		char* 	stop;

		if ((start = memmem(start, size, PEM_START_TAG, PEM_START_TAG_LEN)) == NULL){
			break;
		}

		start += PEM_START_TAG_LEN;
		size = chunk->size - (start - chunk->buffer);

		if ((stop = memmem(start, min(size, PEM_MAX_LENGTH), PEM_STOP_TAG, PEM_STOP_TAG_LEN)) == NULL){
			continue;
		}

		if ((tmp = malloc(stop - start)) == NULL){
			log_err("unable to allocate memory");
			continue;
		}

		for (i = 0, j = 0; i < (size_t)(stop - start); i++){
			if (start[i] == '\n' || start[i] == '\r'){
				continue;
			}
			tmp[j++] = start[i];
		}

		if (j % 4){
			free(tmp);
			continue;
		}

		sub_chunk.buffer = (char*)base64_decode(tmp, j, &sub_chunk.size);
		free(tmp);

		if (sub_chunk.buffer != NULL){
			struct ber_fields bf;

			if (!ber_parse(&sub_chunk, 0, sub_chunk.size, &bf)){
				if (bf.nb_field == 1 && (bf.field_type[0] == 0x30 || bf.field_type[0] == 0x10)){
					if (ber_parse(&sub_chunk, bf.field_start[0], bf.field_length[0], &bf)){
						free(sub_chunk.buffer);
						continue;
					}
				}

				if (!ber_match_rsa_pri_key(&bf)){
					uint32_t k;

					multiColumnPrinter_print_horizontal_separator(printer);

					for (k = 0; k < bf.nb_field; k++){
						searchCryptoKey_report_success(sub_chunk.buffer + bf.field_start[k], bf.field_length[k], chunk->offset + (start - chunk->buffer), _LITTLE_ENDIAN, "PEM RSA", ber_frt_rsa_pri_key[k].desc, chunk->file_name, printer);
					}

					multiColumnPrinter_print_horizontal_separator(printer);
				}
			}

			free(sub_chunk.buffer);
		}
	}
}
