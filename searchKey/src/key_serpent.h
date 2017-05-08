#ifndef KEY_SERPENT_H
#define KEY_SERPENT_H

#include <stdint.h>

#include "util.h"
#include "multiColumn.h"

#define init_serpent_key 0

void search_serpent_key(struct fileChunk* chunk, struct multiColumnPrinter* printer);

#define clean_serpent_key

#endif
