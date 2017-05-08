#ifndef KEY_BER_H
#define KEY_BER_H

#include "util.h"
#include "multiColumn.h"

#define init_ber_key 0

void search_ber_key(struct fileChunk* chunk, struct multiColumnPrinter* printer);

#define clean_ber_key

#endif
