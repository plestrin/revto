#ifndef SEARCHCRYPTOKEY_H
#define SEARCHCRYPTOKEY_H

#include "multiColumn.h"

enum endianness {
	_BIG_ENDIAN,
	_LITTLE_ENDIAN
};

void searchCryptoKey_report_success(const char* buffer, size_t size, off_t offset, enum endianness endian, const char* name, const char* enc_dec_desc, const char* file_name, struct multiColumnPrinter* printer);

#endif
