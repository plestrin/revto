#ifndef KEY_AES_H
#define KEY_AES_H

#include <stdint.h>

#include "util.h"
#include "multiColumn.h"

#define init_aes_key 0

void search_AES128_enc_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

void search_AES128_dec_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

void search_AES128_enc_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

void search_AES128_dec_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

void search_AES192_enc_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

void search_AES192_dec_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

void search_AES192_enc_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

void search_AES192_dec_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

void search_AES256_enc_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

void search_AES256_dec_key_big_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

void search_AES256_enc_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

void search_AES256_dec_key_little_endian(struct fileChunk* chunk, struct multiColumnPrinter* printer);

#define clean_aes_key

#endif