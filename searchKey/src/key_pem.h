#ifndef KEY_PEM_H
#define KEY_PEM_H

#include "util.h"
#include "multiColumn.h"

#define init_pem_key 0

void search_pem_key(struct fileChunk* chunk, struct multiColumnPrinter* printer);

#define clean_pem_key

#endif
