#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "util.h"

void* mapFile_map(const char* file_name, uint64_t* size){
	int 				file;
	struct stat 		sb;
	void*				buffer = MAP_FAILED;

	file = open(file_name, O_RDONLY);
	if (file == -1){
		log_err_m("Unable to open file %s read only: %s", file_name, strerror(errno));
		return NULL;
	}

	if (fstat(file, &sb) < 0){
		log_err("Unable to read file size");
		close(file);
		return NULL;
	}

	*size = sb.st_size;
	if (sb.st_size > 0){
		buffer = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, file, 0);
		if (buffer == MAP_FAILED){
			log_err_m("Unable to map file: %s", strerror(errno));
			buffer = NULL;
		}
	}
	close(file);

	return buffer;
}

int32_t fileChunk_get_next(struct fileChunk* chunk){
	struct stat sb;
	uint64_t 	map_length;

	if (chunk->file == -1){
		chunk->file = open(chunk->file_name, O_RDONLY);
		if (chunk->file == -1){
			log_err_m("Unable to open file %s read only: %s", chunk->file_name, strerror(errno));
			return -1;
		}

		if (fstat(chunk->file, &sb) < 0){
			log_err("Unable to read file size");
			close(chunk->file);
			return -1;
		}

		chunk->file_length = sb.st_size;
		chunk->buffer = NULL;
		chunk->length = 0;
		chunk->offset = 0;
	}

	if (chunk->buffer != NULL && chunk->length > 0){
		munmap(chunk->buffer, chunk->length);
		chunk->offset += chunk->length;
		chunk->buffer = NULL;
		chunk->length = 0;
	}

	if (chunk->offset == chunk->file_length){
		close(chunk->file);
		chunk->file = -1;
		return 1;
	}
	else if (chunk->offset > 0){
		chunk->offset = (chunk->offset > FILECHUNCK_OVERLAP) ? (chunk->offset - FILECHUNCK_OVERLAP) : 0;
	}

	map_length = (chunk->file_length - chunk->offset > FILECHUNCK_MAX_LENGTH) ? FILECHUNCK_MAX_LENGTH : (chunk->file_length - chunk->offset);
	chunk->buffer = mmap(NULL,  map_length, PROT_READ, MAP_PRIVATE, chunk->file, chunk->offset);
	if (chunk->buffer == MAP_FAILED){
		close(chunk->file);
		log_err_m("Unable to map file: %s", strerror(errno));
		return -1;
	}

	chunk->length = map_length;

	return 0;
}

void inv_endian(char* buffer, uint32_t size){
	uint32_t i;

	if (size & 0x00000003){
		log_err_m("Size %u is not a multiple of 4", size);
		return;
	}

	for (i = 0; i < (size >> 2); i++){
		*((uint32_t*)buffer + i) =__builtin_bswap32(*((uint32_t*)buffer + i));
	}
}

void fprintBuffer_raw(FILE* file, char* buffer, uint64_t buffer_length){
	uint64_t 	i;
	char 		hexa[16] = {'0', '1', '2', '3', '4' , '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	for (i = 0; i < buffer_length; i++){
		fprintf(file, "%c%c", hexa[(buffer[i] >> 4) & 0x0f], hexa[buffer[i] & 0x0f]);
	}
}

void fprintBuffer_raw_inv_endian(FILE* file, char* buffer, uint64_t buffer_length){
	uint64_t 	i;
	char 		hexa[16] = {'0', '1', '2', '3', '4' , '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	if (buffer_length % 4){
		log_err("Buffer length must be a multiple of 4");
		return;
	}

	for (i = 0; i < buffer_length; i ++){
		fprintf(file, "%c%c", hexa[(buffer[4*(i/4 + 1) - (i%4) - 1] >> 4) & 0x0f], hexa[buffer[4*(i/4 + 1) - (i%4) - 1] & 0x0f]);
	}
}

void sprintBuffer_raw(char* str, char* buffer, uint64_t buffer_length){
	uint64_t 	i;
	char 		hexa[16] = {'0', '1', '2', '3', '4' , '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	int32_t 	pointer;

	for (i = 0; i < buffer_length; i++){
		pointer = sprintf(str, "%c%c", hexa[(buffer[i] >> 4) & 0x0f], hexa[buffer[i] & 0x0f]);
		if (pointer > 0){
			str += pointer;
		}
		else{
			log_err("snprintf returns error code");
			break;
		}
	}
}

void sprintBuffer_raw_inv_endian(char* str, char* buffer, uint64_t buffer_length){
	uint64_t 	i;
	char 		hexa[16] = {'0', '1', '2', '3', '4' , '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	int32_t 	pointer;

	if (buffer_length % 4){
		log_err("Buffer length must be a multiple of 4");
		return;
	}

	for (i = 0; i < buffer_length; i++){
		pointer = sprintf(str, "%c%c", hexa[(buffer[4*(i/4 + 1) - (i%4) - 1] >> 4) & 0x0f], hexa[buffer[4*(i/4 + 1) - (i%4) - 1] & 0x0f]);
		if (pointer > 0){
			str += pointer;
		}
		else{
			log_err("snprintf returns error code");
			break;
		}
	}
}
