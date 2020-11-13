#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <string.h>

#define log_err(M) fprintf(stderr, "[ERROR] (%s:%d) " M "\n", __FILE__, __LINE__)

#define log_warn(M) fprintf(stderr, "[WARN] (%s:%d) " M "\n", __FILE__, __LINE__)

#define log_info(M) fprintf(stderr, "[INFO] (%s:%d) " M "\n", __FILE__, __LINE__)

#define log_err_m(M, ...) fprintf(stderr, "[ERROR] (%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define log_warn_m(M, ...) fprintf(stderr, "[WARN] (%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define log_info_m(M, ...) fprintf(stderr, "[INFO] (%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#ifndef FILECHUNCK_MAX_SIZE
#define FILECHUNCK_MAX_SIZE 0x40000
#endif
#ifndef FILECHUNCK_OVERLAP
#define FILECHUNCK_OVERLAP 0x1000
#endif

struct fileChunk {
	FILE* 		file;
	const char* file_name;
	char* 		buffer;
	size_t 		size;
	off_t 		offset;
};

#define fileChunk_init(chunk, file_, file_name_) 	\
	(chunk).file 		= file_; 					\
	(chunk).file_name 	= file_name_; 				\
	(chunk).buffer 		= NULL;

int fileChunk_open(struct fileChunk* chunk, const char* file_name);
size_t fileChunk_get_next(struct fileChunk* chunk);

#define fileChunk_get_offset(chunk) ((chunk)->offset)
#define fileChunk_close(chunk) fclose((chunk).file)
#define fileChunk_clean(chunk) 	\
	free((chunk).buffer); 		\
	(chunk).buffer = NULL;

void inv_endian(char* buffer, size_t size);

void fprintBuffer_raw(FILE* file, const char* buffer, size_t buffer_length);
void sprintBuffer_raw(char* str, const char* buffer, size_t buffer_length);

void fprintBuffer_raw_inv_endian(FILE* file, const char* buffer, size_t buffer_length);
void sprintBuffer_raw_inv_endian(char* str, const char* buffer, size_t buffer_length);

#ifndef min
#define min(a, b) (((a) > (b)) ? (b) : (a))
#endif
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

unsigned char* base64_decode(const char* data, size_t input_length, size_t *output_length);

#endif
