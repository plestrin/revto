#ifndef KEY_DES_H
#define KEY_DES_H

#include <stdint.h>

#include "util.h"
#include "multiColumn.h"

#define init_des_key 0

void search_des_key(struct fileChunk* chunk, struct multiColumnPrinter* printer);

#define clean_des_key

#endif