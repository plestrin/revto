#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define log_err(M) fprintf(stderr, "[ERROR] (%s:%d:) " M "\n", __FILE__, __LINE__)

#define log_warn(M) fprintf(stderr, "[WARN] (%s:%d:) " M "\n", __FILE__, __LINE__)

#define log_info(M) fprintf(stderr, "[INFO] (%s:%d) " M "\n", __FILE__, __LINE__)

#define log_err_m(M, ...) fprintf(stderr, "[ERROR] (%s:%d:) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define log_warn_m(M, ...) fprintf(stderr, "[WARN] (%s:%d:) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define log_info_m(M, ...) fprintf(stderr, "[INFO] (%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

void* mapFile_map(const char* file_name, uint64_t* size);

#ifndef FILECHUNCK_MAX_LENGTH
#define FILECHUNCK_MAX_LENGTH 	4096000
#endif
#ifndef FILECHUNCK_OVERLAP
#define FILECHUNCK_OVERLAP 		4096
#endif

struct fileChunk{
	char* 		file_name;
	int 		file;
	uint64_t 	file_length;
	char* 		buffer;
	uint64_t 	length;
	uint64_t 	offset;
};

#define fileChunk_init(chunk, file_name_) 		\
	(chunk).file_name = file_name_; 			\
	(chunk).file = -1; 							\
	(chunk).buffer = NULL

int32_t fileChunk_get_next(struct fileChunk* chunk);

void inv_endian(char* buffer, uint32_t size);

void fprintBuffer_raw(FILE* file, char* buffer, uint64_t buffer_length);
void sprintBuffer_raw(char* str, char* buffer, uint64_t buffer_length);

void fprintBuffer_raw_inv_endian(FILE* file, char* buffer, uint64_t buffer_length);
void sprintBuffer_raw_inv_endian(char* str, char* buffer, uint64_t buffer_length);

#ifndef min
#define min(a, b) (((a) > (b)) ? (b) : (a))
#endif
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#endif
