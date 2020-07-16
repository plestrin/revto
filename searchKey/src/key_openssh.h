#ifndef KEY_OPENSSH_H
#define KEY_OPENSSH_H

#include "util.h"
#include "multiColumn.h"

#define init_openssh_key 0

void search_openssh_key(struct fileChunk* chunk, struct multiColumnPrinter* printer);

#define clean_openssh_key

#endif
