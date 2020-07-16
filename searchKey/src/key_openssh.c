#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "key_openssh.h"

#include "searchCryptoKey.h"
#include "util.h"

#if ENABLE_PUB
static int openssl_read_size(char* buffer, size_t* size_ptr, size_t* off_ptr, uint32_t* value){
	if (4 > *size_ptr){
		return -1;
	}

	*value = __builtin_bswap32(*(uint32_t*)(buffer + *off_ptr));
	*size_ptr = *size_ptr - 4;
	*off_ptr = *off_ptr + 4;

	return 0;
}

static void search_openssh_dss(char* buffer, size_t size, size_t offset, struct multiColumnPrinter* printer, const char* file_name){
	uint32_t item_size;

	char* p;
	size_t p_size;
	size_t p_off;
	char* q;
	size_t q_size;
	size_t q_off;
	char* g;
	size_t g_size;
	size_t g_off;
	char* u;
	size_t u_size;
	size_t u_off;

	if (openssl_read_size(buffer, &size, &offset, &item_size)){
		return;
	}
	if (item_size > size){
		return;
	}

	size -= item_size;
	offset += item_size;

	if (openssl_read_size(buffer, &size, &offset, &item_size)){
		return;
	}
	if (!item_size || item_size > size){
		return;
	}

	p = buffer + offset;
	p_size = item_size;
	p_off = offset;

	size -= item_size;
	offset += item_size;

	if (openssl_read_size(buffer, &size, &offset, &item_size)){
		return;
	}
	if (!item_size || item_size > size){
		return;
	}

	q = buffer + offset;
	q_size = item_size;
	q_off = offset;

	size -= item_size;
	offset += item_size;

	if (openssl_read_size(buffer, &size, &offset, &item_size)){
		return;
	}
	if (!item_size || item_size > size){
		return;
	}

	g = buffer + offset;
	g_size = item_size;
	g_off = offset;

	size -= item_size;
	offset += item_size;

	if (openssl_read_size(buffer, &size, &offset, &item_size)){
		return;
	}
	if (!item_size || item_size > size){
		return;
	}

	u = buffer + offset;
	u_size = item_size;
	u_off = offset;

	multiColumnPrinter_print_horizontal_separator(printer);

	searchCryptoKey_report_success(p, p_size, p_off, _LITTLE_ENDIAN, "ssh-dss p", "pub", file_name, printer);
	searchCryptoKey_report_success(q, q_size, q_off, _LITTLE_ENDIAN, "ssh-dss q", "pub", file_name, printer);
	searchCryptoKey_report_success(g, g_size, g_off, _LITTLE_ENDIAN, "ssh-dss g", "pub", file_name, printer);
	searchCryptoKey_report_success(u, u_size, u_off, _LITTLE_ENDIAN, "ssh-dss pub", "pub", file_name, printer);

	multiColumnPrinter_print_horizontal_separator(printer);
}
#else
#define search_openssh_dss(buffer, size, offset, printer, file_name)
#endif

#define OPENSSH_MIN_SIZE (8 + 7) // size + "ssh-dss" + size

void search_openssh_key(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	size_t 	i;
	uint32_t name_size;

	if (chunk->size < OPENSSH_MIN_SIZE){
		return;
	}

	for (i = 0; i < chunk->size - OPENSSH_MIN_SIZE + 1; i += 1){
		name_size = __builtin_bswap32(*(uint32_t*)(chunk->buffer + i));
		if (name_size == 7 && !memcmp(chunk->buffer + i + 4, "ssh-dss", 7)){
			search_openssh_dss(chunk->buffer, chunk->size - i, i, printer, chunk->file_name);
		}
	}
}
