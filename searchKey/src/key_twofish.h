#ifndef KEY_TWOFISH_H
#define KEY_TWOFISH_H

#include <stdint.h>

#include "util.h"
#include "multiColumn.h"

int32_t init_twofish192();
void clean_twofish192();

int32_t init_twofish256();
void clean_twofish256();

#define init_twofish_key (init_twofish192() || init_twofish256())

void search_twofish_key(struct fileChunk* chunk, struct multiColumnPrinter* printer);

#define clean_twofish_key 	\
	clean_twofish192(); 	\
	clean_twofish256();

#endif
