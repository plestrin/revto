#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "key_ber.h"

#include "searchCryptoKey.h"

#define BER_MIN_LENGTH 5
#define BER_FIELD_DESC_MAX_LENGTH 256

/* #define BER_KEY_DEBUG */

#ifdef BER_KEY_DEBUG
#define log_debug(M) log_info(M)
#define log_debug_m(M, ...) log_info_m(M, ##__VA_ARGS__)
#else
#define log_debug(M)
#define log_debug_m(M, ...)
#endif

static const uint8_t ber_valid_identifier[64] = {
	1, /* 0x00 - P - EOC 		*/
	1, /* 0x01 - P - bool 		*/
	1, /* 0x02 - P - int 		*/
	1, /* 0x03 - P - bit str 	*/
	1, /* 0x04 - P - byte str 	*/
	1, /* 0x05 - P - NULL 		*/
	1, /* 0x06 - P - obj id 	*/
	1, /* 0x07 - P - obj desc 	*/
	0, /* 0x08 - P - ext 		*/
	1, /* 0x09 - P - real 		*/
	1, /* 0x0a - P - enum 		*/
	0, /* 0x0b - P - embedded 	*/
	1, /* 0x0c - P - utf8 		*/
	1, /* 0x0d - P - rel OID 	*/
	1, /* 0x0e - P - reserved 	*/
	1, /* 0x0f - P - reserved 	*/
	0, /* 0x10 - P - seq 		*/
	0, /* 0x11 - P - set 		*/
	1, /* 0x12 - P - num str 	*/
	1, /* 0x13 - P - print str 	*/
	1, /* 0x14 - P - T61 		*/
	1, /* 0x15 - P - video str 	*/
	1, /* 0x16 - P - IA5 		*/
	1, /* 0x17 - P - UTC time 	*/
	1, /* 0x18 - P - gen time 	*/
	1, /* 0x19 - P - graph str 	*/
	1, /* 0x1a - P - vis str 	*/
	1, /* 0x1b - P - gen str 	*/
	1, /* 0x1c - P - uni str 	*/
	1, /* 0x1d - P - char str 	*/
	1, /* 0x1e - P - bmp str 	*/
	1, /* 0x1f - P - long form 	*/

	0, /* 0x20 - C - EOC 		*/
	0, /* 0x21 - C - bool 		*/
	0, /* 0x22 - C - int 		*/
	1, /* 0x23 - C - bit str 	*/
	1, /* 0x24 - C - byte str 	*/
	0, /* 0x25 - C - NULL 		*/
	0, /* 0x26 - C - obj id 	*/
	1, /* 0x27 - C - obj desc 	*/
	1, /* 0x28 - C - ext 		*/
	0, /* 0x29 - C - real 		*/
	0, /* 0x2a - C - enum 		*/
	1, /* 0x2b - C - embedded 	*/
	1, /* 0x2c - C - utf8 		*/
	0, /* 0x2d - C - rel OID 	*/
	1, /* 0x2e - C - reserved 	*/
	1, /* 0x2f - C - reserved 	*/
	1, /* 0x30 - C - seq 		*/
	1, /* 0x31 - C - set 		*/
	1, /* 0x32 - C - num str 	*/
	1, /* 0x33 - C - print str 	*/
	1, /* 0x34 - C - T61 		*/
	1, /* 0x35 - C - video str 	*/
	1, /* 0x36 - C - IA5 		*/
	1, /* 0x37 - C - UTC time 	*/
	1, /* 0x38 - C - gen time 	*/
	1, /* 0x39 - C - graph str 	*/
	1, /* 0x3a - C - vis str 	*/
	1, /* 0x3b - C - gen str 	*/
	1, /* 0x3c - C - uni str 	*/
	1, /* 0x3d - C - char str 	*/
	1, /* 0x3e - C - bmp str 	*/
	1  /* 0x3f - C - long form 	*/
};

struct berField{
	uint8_t must_print;
	char 	desc[BER_FIELD_DESC_MAX_LENGTH];
};

static inline void ber_print(struct fileChunk* chunk, size_t* field_start, size_t* field_length, const struct berField* fields, uint32_t nb_field, const char* name, struct multiColumnPrinter* printer){
	uint32_t i;

	for (i = 0; i < nb_field; i++){
		searchCryptoKey_report_success(chunk->buffer + field_start[i], field_length[i], chunk->offset + field_start[i], _LITTLE_ENDIAN, name, fields[i].desc, chunk->file_name, printer);
	}
}

#define BER_FRT_RSA_PRI_KEY_NB_FIELD 9
static const struct berField ber_frt_rsa_pri_key[BER_FRT_RSA_PRI_KEY_NB_FIELD] = {
	{
		.must_print = 0,
		.desc = "ver"
	},
	{
		.must_print = 1,
		.desc = "mod"
	},
	{
		.must_print = 1,
		.desc = "pub-exp"
	},
	{
		.must_print = 1,
		.desc = "pri-exp"
	},
	{
		.must_print = 1,
		.desc = "p1"
	},
	{
		.must_print = 1,
		.desc = "p2"
	},
	{
		.must_print = 1,
		.desc = "exp1"
	},
	{
		.must_print = 1,
		.desc = "exp2"
	},
	{
		.must_print = 1,
		.desc = "coef"
	}
};

static int32_t ber_rsa_pri_key_parse(struct fileChunk* chunk, size_t* field_start, uint8_t* field_type, size_t* field_length, struct multiColumnPrinter* printer){
	if (field_type[0] == 0x02 && field_length[0] == 1){
		ber_print(chunk, field_start, field_length, ber_frt_rsa_pri_key, BER_FRT_RSA_PRI_KEY_NB_FIELD, "BER RSA", printer);
		return 0;
	}

	return -1;
}

#define BER_FRT_RSA_PUB_KEY_NB_FIELD 2
static const struct berField ber_frt_rsa_pub_key[BER_FRT_RSA_PUB_KEY_NB_FIELD] = {
	{
		.must_print = 1,
		.desc = "mod"
	},
	{
		.must_print = 1,
		.desc = "pub-exp"
	}
};

static int32_t ber_rsa_pub_key_parse(struct fileChunk* chunk, size_t* field_start, uint8_t* field_type, size_t* field_length, struct multiColumnPrinter* printer){
	if (field_type[0] == 0x02 && field_type[1] == 0x02 && field_length[0] >= field_length[1] && field_length[1] > 0){
		ber_print(chunk, field_start, field_length, ber_frt_rsa_pub_key, BER_FRT_RSA_PUB_KEY_NB_FIELD, "BER RSA", printer);
		return 0;
	}

	return -1;
}

#define BER_FRT_DSA_PRI_KEY_NB_FIELD 6
static const struct berField ber_frt_dsa_pri_key[BER_FRT_DSA_PRI_KEY_NB_FIELD] = {
	{
		.must_print = 0,
		.desc = "ver"
	},
	{
		.must_print = 1,
		.desc = "P"
	},
	{
		.must_print = 1,
		.desc = "Q"
	},
	{
		.must_print = 1,
		.desc = "G"
	},
	{
		.must_print = 1,
		.desc = "pub"
	},
	{
		.must_print = 1,
		.desc = "priv"
	}
};

static int32_t ber_dsa_pri_key_parse(struct fileChunk* chunk, size_t* field_start, uint8_t* field_type, size_t* field_length, struct multiColumnPrinter* printer){
	if (field_type[0] == 0x02 && field_length[0] == 1){
		if (field_length[1] >= field_length[2]){ /* Q | (P - 1) */
			ber_print(chunk, field_start, field_length, ber_frt_dsa_pri_key, BER_FRT_DSA_PRI_KEY_NB_FIELD, "BER DSA", printer);
			return 0;
		}
	}

	return -1;
}

#define BER_FRT_DSA_PUB_KEY_NB_FIELD 3
static const struct berField ber_frt_dsa_pub_key[BER_FRT_DSA_PUB_KEY_NB_FIELD] = {
	{
		.must_print = 1,
		.desc = "P"
	},
	{
		.must_print = 1,
		.desc = "Q"
	},
	{
		.must_print = 1,
		.desc = "G"
	},
};

static int32_t ber_dsa_pub_key_parse(struct fileChunk* chunk, size_t* field_start, uint8_t* field_type, size_t* field_length, struct multiColumnPrinter* printer){
	if (field_type[0] == 0x02 && field_type[2] == 0x02){
		if (field_length[0] >= field_length[1]){ /* Q | (P - 1) */
			ber_print(chunk, field_start, field_length, ber_frt_dsa_pub_key, BER_FRT_DSA_PUB_KEY_NB_FIELD, "BER DSA", printer);
			return 0;
		}
	}

	return -1;
}

#define BER_FRT_MAX_FIELD 9 /* must be updated, if one adds a new format */

enum berLength{
	BER_LENGTH_INVALID,
	BER_LENGTH_INDEFINITE,
	BER_LENGTH_DEFINITE
};

static enum berLength ber_get_length_type(const uint8_t* buffer, size_t length){
	if (!length){
		return BER_LENGTH_INVALID;
	}
	else if (buffer[0] == 0x80){
		return BER_LENGTH_INDEFINITE;
	}
	else if (buffer[0] == 0xff){
		return BER_LENGTH_INVALID;
	}
	else if ((buffer[0] & 0x80) && (size_t)(buffer[0] & 0x7f) > min(length - 1, 8)){
		return BER_LENGTH_INVALID;
	}
	else{
		return BER_LENGTH_DEFINITE;
	}
}

static size_t ber_get_indefinite_length(const uint8_t* buffer, size_t length){
	size_t i;

	for (i = 1; i + 1 < length; i++){
		if (!((buffer[i] | buffer[i + 1]) & 0x3f)){
			return i - 1;
		}
	}

	return length;
}

static size_t ber_get_definite_length(const uint8_t* buffer, size_t* offset){
	uint32_t i;
	uint64_t result;

	if (buffer[0] & 0x80){
		*offset = (uint32_t)(buffer[0] & 0x7f) + 1;

		for (i = 1, result = 0; i < *offset; i++){
			result = result << 8;
			result |= (uint64_t)(buffer[i]);
		}
	}
	else{
		*offset = 1;
		result = (uint64_t)(buffer[0]);
	}

	return result;
}

static uint32_t ber_parse(struct fileChunk* chunk, size_t start, size_t length, struct multiColumnPrinter* printer){
	size_t 		i;
	size_t 		field_start[BER_FRT_MAX_FIELD];
	uint8_t 	field_type[BER_FRT_MAX_FIELD];
	size_t 		field_length[BER_FRT_MAX_FIELD];
	uint32_t 	nb_field;

	log_debug_m("starting BER format @ %llu length %u", chunk->offset + start, length);

	for (i = 0, nb_field = 0; i + 1 < length; ){
		if (nb_field == BER_FRT_MAX_FIELD){
			log_debug("\tBER: the max number of fields have been reached -> exit");
			return -1;
		}

		if (!ber_valid_identifier[chunk->buffer[start + i] & 0x3f]){
			log_debug("\tBER: invalid identifier -> exit");
			return -1;
		}

		field_type[nb_field] = chunk->buffer[start + i] & 0x1f;
		i ++;

		switch (ber_get_length_type((uint8_t*)(chunk->buffer + start + i), length - i)){
			case BER_LENGTH_INVALID 	: {
				log_debug_m("\tBER: invalid length @ %llu -> exit", chunk->offset + start + i);
				return -1;
			}
			case BER_LENGTH_INDEFINITE 	: {
				if (chunk->buffer[start + i - 1] & 0x20){
					size_t l;

					l = ber_get_indefinite_length((uint8_t*)(chunk->buffer + start + i), length - i);

					if (l == length - i){
						log_debug_m("\tBER: invalid indefinite length @ %llu -> exit", chunk->offset + start + i);
						return -1;
					}

					log_debug_m("\tBER: length: %llu @ %llu ", l, chunk->offset + start + i);

					i += 1;
					field_start[nb_field] = start + i;
					field_length[nb_field] = l;
					nb_field ++;
					i += l + 2;
				}
				else{
					log_debug_m("\tBER: indefinite length must be used with a composite type @ %llu -> exit", chunk->offset + start + i);
					return -1;
				}

				break;
			}
			case BER_LENGTH_DEFINITE 	: {
				size_t l;
				size_t 	offset;

				l = (size_t)ber_get_definite_length((uint8_t*)(chunk->buffer + start + i), &offset);

				log_debug_m("\tBER: length: %llu @ %llu ", l, chunk->offset + start + i);

				i += offset;
				field_start[nb_field] = start + i;
				field_length[nb_field] = l;
				nb_field ++;
				i += l;

				break;
			}
		}
	}

	if (i != length){
		log_debug_m("\tBER: layout size %llu differs from the sum of the fields %llu", length, i);
		return -1;
	}

	log_debug_m("\tBER: %u field(s)", nb_field);

	if (nb_field == BER_FRT_RSA_PRI_KEY_NB_FIELD){
		if (!ber_rsa_pri_key_parse(chunk, field_start, field_type, field_length, printer)){
			return 0;
		}
	}
	if (nb_field == BER_FRT_RSA_PUB_KEY_NB_FIELD){
		if (!ber_rsa_pub_key_parse(chunk, field_start, field_type, field_length, printer)){
			return 0;
		}
	}
	if (nb_field == BER_FRT_DSA_PRI_KEY_NB_FIELD){
		if (!ber_dsa_pri_key_parse(chunk, field_start, field_type, field_length, printer)){
			return 0;
		}
	}
	if (nb_field == BER_FRT_DSA_PUB_KEY_NB_FIELD){
		if (!ber_dsa_pub_key_parse(chunk, field_start, field_type, field_length, printer)){
			return 0;
		}
	}

	return -1;
}

void search_ber_key(struct fileChunk* chunk, struct multiColumnPrinter* printer){
	size_t i;

	if (chunk->size < BER_MIN_LENGTH){
		return;
	}

	for (i = 0; i < chunk->size - BER_MIN_LENGTH + 1; i++){
		if (chunk->buffer[i] == 0x30){
			switch (ber_get_length_type((uint8_t*)(chunk->buffer + i + 1), chunk->size - i - 1)){
				case BER_LENGTH_INVALID 	: {break;}
				case BER_LENGTH_INDEFINITE 	: {
					size_t length;

					length = ber_get_indefinite_length((uint8_t*)(chunk->buffer + i + 1), chunk->size - i - 1);
					if (length != chunk->size - i - 1){
						if (!ber_parse(chunk, i + 2, length, printer)){
							i += 1 + length + 2;
						}
					}

					break;
				}
				case BER_LENGTH_DEFINITE 	: {
					size_t length;
					size_t offset;

					length = (size_t)ber_get_definite_length((uint8_t*)(chunk->buffer + i + 1), &offset);
					if (length + i + 1 + offset <= chunk->size){
						if (!ber_parse(chunk, i + 1 + offset, length, printer)){
							i += offset + length;
						}
					}

					break;
				}
			}
		}
	}
}
