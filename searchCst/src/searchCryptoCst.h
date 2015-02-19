#ifndef SEARCHCRYPTOCST_H
#define SEARCHCRYPTOCST_H

#include <stdint.h>

enum cstType{
	CST_TYPE_ARRAY,
	CST_TYPE_LISTE,
	CST_TYPE_INVALID
};

#define CST_NAME_MAX_LENGTH 64

struct cstScore{
	uint64_t min_offset;
	uint64_t max_offset;
	uint8_t* score;
};

struct cstDescriptor{
	enum cstType 		type;
	uint32_t 			nb_element;
	uint8_t 			element_size;
	char 				name[CST_NAME_MAX_LENGTH];
	const char* 		ptr;
	uint32_t 			score_threshold;
	struct cstScore* 	score_header;
};

#define cstDescriptor_is_valid(desc) ((desc).type != CST_TYPE_INVALID)

#endif