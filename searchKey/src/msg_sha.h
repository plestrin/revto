#ifndef MSG_SHA_H
#define MSG_SHA_H

#include <stdint.h>

#include "util.h"
#include "multiColumn.h"

#define init_sha_msg 0

void search_sha1_msg(struct fileChunk* chunk, struct multiColumnPrinter* printer);
void search_sha256_msg(struct fileChunk* chunk, struct multiColumnPrinter* printer);
void search_sha512_msg(struct fileChunk* chunk, struct multiColumnPrinter* printer);

#define clean_sha_msg

#endif
