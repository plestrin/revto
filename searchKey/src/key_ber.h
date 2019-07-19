#ifndef KEY_BER_H
#define KEY_BER_H

#include "util.h"
#include "multiColumn.h"

#define init_ber_key 0

#define BER_FRT_MAX_FIELD 9 /* must be updated, if one adds a new format */

struct ber_fields {
	size_t 		field_start[BER_FRT_MAX_FIELD];
	uint8_t 	field_type[BER_FRT_MAX_FIELD];
	size_t 		field_length[BER_FRT_MAX_FIELD];
	uint32_t 	nb_field;
};

void search_ber_key(struct fileChunk* chunk, struct multiColumnPrinter* printer);

int ber_parse(struct fileChunk* chunk, size_t start, size_t length, struct ber_fields* bf);

int ber_match_rsa_pri_key(struct ber_fields* bf);
int ber_match_dsa_pri_key(struct ber_fields* bf);
#ifdef ENABLE_PUB
int ber_match_rsa_pub_key(struct ber_fields* bf);
int ber_match_dsa_pub_key(struct ber_fields* bf);
#endif

#define BER_FIELD_DESC_MAX_LENGTH 256

struct ber_field_meta_print {
	uint8_t must_print;
	char 	desc[BER_FIELD_DESC_MAX_LENGTH];
};

void ber_print(struct fileChunk* chunk, struct ber_fields* bf, const struct ber_field_meta_print* bfmp, const char* name, struct multiColumnPrinter* printer);

#define clean_ber_key

#endif
