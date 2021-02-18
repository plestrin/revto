#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "key_openssh.h"

#include "searchCryptoKey.h"
#include "util.h"

static int openssl_read_size(char* buffer, size_t* size_ptr, size_t* off_ptr, uint32_t* value){
	if (4 > *size_ptr){
		return -1;
	}

	*value = __builtin_bswap32(*(uint32_t*)(buffer + *off_ptr));
	*size_ptr = *size_ptr - 4;
	*off_ptr = *off_ptr + 4;

	return 0;
}

static void search_openssh_dss(struct fileChunk* chunk, size_t size, size_t offset, struct multiColumnPrinter* printer){
	uint32_t item_size;

	char* p;
	size_t p_size;
	off_t p_off;
	char* q;
	size_t q_size;
	off_t q_off;
	char* g;
	size_t g_size;
	off_t g_off;
	char* y;
	size_t y_size;
	off_t y_off;
	char* x;
	size_t x_size;
	off_t x_off;

	if (openssl_read_size(chunk->buffer, &size, &offset, &item_size)){
		return;
	}
	if (item_size > size){
		return;
	}

	size -= item_size;
	offset += item_size;

	if (openssl_read_size(chunk->buffer, &size, &offset, &item_size)){
		return;
	}
	if (!item_size || item_size > size){
		return;
	}

	p = chunk->buffer + offset;
	p_size = item_size;
	p_off = offset + chunk->offset;

	size -= item_size;
	offset += item_size;

	if (openssl_read_size(chunk->buffer, &size, &offset, &item_size)){
		return;
	}
	if (!item_size || item_size > size){
		return;
	}

	q = chunk->buffer + offset;
	q_size = item_size;
	q_off = offset + chunk->offset;

	size -= item_size;
	offset += item_size;

	if (openssl_read_size(chunk->buffer, &size, &offset, &item_size)){
		return;
	}
	if (!item_size || item_size > size){
		return;
	}

	g = chunk->buffer + offset;
	g_size = item_size;
	g_off = offset + chunk->offset;

	size -= item_size;
	offset += item_size;

	if (openssl_read_size(chunk->buffer, &size, &offset, &item_size)){
		return;
	}
	if (!item_size || item_size > size){
		return;
	}

	y = chunk->buffer + offset;
	y_size = item_size;
	y_off = offset + chunk->offset;

	size -= item_size;
	offset += item_size;

	if (openssl_read_size(chunk->buffer, &size, &offset, &item_size) || !item_size || item_size > size){
		#if ENABLE_PUB
		x = NULL;
		x_size = 0;
		x_off = 0;
		#else
		return;
		#endif
	}
	else {
		x = chunk->buffer + offset;
		x_size = item_size;
		x_off = offset + chunk->offset;
	}

	multiColumnPrinter_print_horizontal_separator(printer);

	searchCryptoKey_report_success(p, p_size, p_off, _LITTLE_ENDIAN, "ssh-dss p", "pub", chunk->file_name, printer);
	searchCryptoKey_report_success(q, q_size, q_off, _LITTLE_ENDIAN, "ssh-dss q", "pub", chunk->file_name, printer);
	searchCryptoKey_report_success(g, g_size, g_off, _LITTLE_ENDIAN, "ssh-dss g", "pub", chunk->file_name, printer);
	searchCryptoKey_report_success(y, y_size, y_off, _LITTLE_ENDIAN, "ssh-dss y", "pub", chunk->file_name, printer);
	if (x != NULL){
		searchCryptoKey_report_success(x, x_size, x_off, _LITTLE_ENDIAN, "ssh-dss x", "priv", chunk->file_name, printer);
	}

	multiColumnPrinter_print_horizontal_separator(printer);
}

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
			search_openssh_dss(chunk, chunk->size - i, i, printer);
		}
	}
}
