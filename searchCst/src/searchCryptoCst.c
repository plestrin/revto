#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "searchCryptoCst.h"
#include "util.h"
#include "multiColumn.h"

extern struct cstDescriptor cst_descriptor[];

struct cst{
	struct cstDescriptor* 	descriptor;
	struct cstScore* 		score;
	uint32_t 				score_offset;
	uint32_t 				size;
	char* 					value;
};

struct acceleratorEntry{
	uint32_t nb_cst;
	uint32_t offset;
};

struct cstEngine{
	struct acceleratorEntry		accelerator[256];
	struct cst* 				cst_buffer;
	struct cstScore* 			score_header_buffer;
	uint8_t* 					score_buffer;
	uint32_t 					score_size;
	char* 						value_buffer;
};

static int32_t searchCryptoCst_init_cstEngine(struct cstEngine* engine);

#define searchCryptoCst_clean_cstEngine(engine) 	\
	free((engine).cst_buffer); 						\
	free((engine).score_header_buffer); 			\
	free((engine).score_buffer); 					\
	free((engine).value_buffer)

#define searchCryptoCst_clean_score(engine) memset((engine).score_buffer, 0, (engine).score_size)

static void searchCryptoCst_report_success(char* file_name, struct multiColumnPrinter* printer);

int main(int32_t argc, char** argv){
	int32_t 					i;
	uint64_t 					j;
	uint32_t 					k;
	struct multiColumnPrinter* 	printer;
	uint8_t* 					buffer;
	uint64_t 					length;
	struct cstEngine 			engine;
	struct cst* 				cst;

	if (searchCryptoCst_init_cstEngine(&engine)){
		log_err("Unable to initialize the constant engine");
		return 0;
	}

	if (argc < 2){
		log_err("Please specify a binary file");
		searchCryptoCst_clean_cstEngine(engine);
		return 0;
	}

	printer = multiColumnPrinter_create(stdout, 5, NULL, NULL, NULL);
	if (printer == NULL){
		log_err("Unable to create multiColumn printer");
	}
	else{
		multiColumnPrinter_set_column_size(printer, 0, 64);
		multiColumnPrinter_set_column_size(printer, 1, 24);
		multiColumnPrinter_set_column_size(printer, 2, 6);
		multiColumnPrinter_set_column_size(printer, 3, 12);
		multiColumnPrinter_set_column_size(printer, 4, 12);

		multiColumnPrinter_set_column_type(printer, 3, MULTICOLUMN_TYPE_HEX_64);
		multiColumnPrinter_set_column_type(printer, 4, MULTICOLUMN_TYPE_HEX_64);

		multiColumnPrinter_set_title(printer, 0, "FILE");
		multiColumnPrinter_set_title(printer, 1, "NAME");
		multiColumnPrinter_set_title(printer, 2, "SCORE");
		multiColumnPrinter_set_title(printer, 3, "MIN OFF");
		multiColumnPrinter_set_title(printer, 4, "MAX OFF");
		
		multiColumnPrinter_print_header(printer);


		for (i = 1; i < argc; i++){
			buffer = (uint8_t*)mapFile_map(argv[i], &length);
			if (buffer == NULL || buffer == MAP_FAILED){
				log_err_m("MapFile failed for: \"%s\"", argv[i]);
				continue;
			}

			searchCryptoCst_clean_score(engine);
			for (j = 0; j < length; j++){
				for (k = 0; k < engine.accelerator[buffer[j]].nb_cst; k++){
					cst = engine.cst_buffer + engine.accelerator[buffer[j]].offset + k;
					if (cst->size <= length - j){
						if (!memcmp(cst->value, buffer + j, cst->size)){
							engine.score_buffer[cst->score_offset] = 1;
							if (cst->score->min_offset > j){
								cst->score->min_offset = j;
							}
							if (cst->score->max_offset < j){
								cst->score->max_offset = j;
							}
						}
					}
				}
			}

			munmap(buffer, length);
			searchCryptoCst_report_success(argv[i], printer);
		}

		multiColumnPrinter_delete(printer);
	}

	searchCryptoCst_clean_cstEngine(engine);

	return 0;
}

static int32_t searchCryptoCst_init_cstEngine(struct cstEngine* engine){
	uint32_t nb_descriptor 	= 0;
	uint32_t nb_cst 		= 0;
	uint32_t value_size 	= 0;
	uint32_t score_size 	= 0;

	uint32_t offset_cst 			= 0;
	uint32_t offset_score_header 	= 0;
	uint32_t offset_value 			= 0;
	uint32_t offset_score 			= 0;

	uint32_t 	i;
	uint32_t 	j;
	struct cst 	tmp;

	for (i = 0; ; i++){
		switch (cst_descriptor[i].type){
			case CST_TYPE_ARRAY : {
				if (cst_descriptor[i].element_size == 1){
					nb_descriptor 	+= 1;
					nb_cst 			+= 1;
					value_size 		+= cst_descriptor[i].element_size * cst_descriptor[i].nb_element;
					score_size 		+= 1;
				}
				else if (cst_descriptor[i].element_size == 4 || cst_descriptor[i].element_size == 8){
					nb_descriptor 	+= 1;
					nb_cst 			+= 2;
					value_size 		+= 2 * cst_descriptor[i].element_size * cst_descriptor[i].nb_element;
					score_size 		+= 1;
				}
				else{
					log_warn_m("This case is not implemented yet, array of element of size %u", cst_descriptor[i].element_size);
				}
				break;
			}
			case CST_TYPE_LISTE : {
				if (cst_descriptor[i].element_size == 4){
					nb_descriptor 	+= 1;
					nb_cst 			+= 2 * cst_descriptor[i].nb_element;
					value_size 		+= 2 * cst_descriptor[i].element_size * cst_descriptor[i].nb_element;
					score_size 		+= cst_descriptor[i].nb_element;
				}
				else{
					log_warn_m("This case is not implemented yet, list of element of size %u", cst_descriptor[i].element_size);
				}
				break;
			}
			case CST_TYPE_INVALID 	: {
				goto next1;
			}
		}
	}

	next1:

	engine->cst_buffer 				= (struct cst*)malloc(sizeof(struct cst) * nb_cst);
	engine->score_header_buffer 	= (struct cstScore*)malloc(sizeof(struct cstScore) * nb_descriptor);
	engine->score_buffer 			= (uint8_t*)malloc(score_size);
	engine->score_size 				= score_size;
	engine->value_buffer 			= (char*)malloc(value_size);

	if (engine->cst_buffer == NULL || engine->score_header_buffer == NULL || engine->score_buffer == NULL || engine->value_buffer == NULL){
		log_err("Unable to allocate memory");

		if (engine->cst_buffer != NULL){
			free(engine->cst_buffer);
		}
		if (engine->score_header_buffer != NULL){
			free(engine->score_header_buffer);
		}
		if (engine->score_buffer != NULL){
			free(engine->score_buffer);
		}
		if (engine->value_buffer != NULL){
			free(engine->value_buffer);
		}

		return -1;
	}

	for (i = 0; ; i++){
		switch (cst_descriptor[i].type){
			case CST_TYPE_ARRAY : {
				if (cst_descriptor[i].element_size == 1){
					cst_descriptor[i].score_header = engine->score_header_buffer + offset_score_header;

					engine->cst_buffer[offset_cst].descriptor 	= cst_descriptor + i;
					engine->cst_buffer[offset_cst].score 		= engine->score_header_buffer + offset_score_header;
					engine->cst_buffer[offset_cst].score_offset = offset_score;
					engine->cst_buffer[offset_cst].size 		= cst_descriptor[i].nb_element * cst_descriptor[i].element_size;
					engine->cst_buffer[offset_cst].value 		= engine->value_buffer + offset_value;

					engine->score_header_buffer[offset_score_header].min_offset = 0xffffffffffffffff;
					engine->score_header_buffer[offset_score_header].max_offset = 0;
					engine->score_header_buffer[offset_score_header].score 		= engine->score_buffer + offset_score;

					memcpy(engine->value_buffer + offset_value, cst_descriptor[i].ptr, cst_descriptor[i].nb_element * cst_descriptor[i].element_size);

					offset_cst 				+= 1;
					offset_score_header 	+= 1;
					offset_value 			+= cst_descriptor[i].nb_element * cst_descriptor[i].element_size;
					offset_score 			+= 1;
				}
				else if (cst_descriptor[i].element_size == 4 || cst_descriptor[i].element_size == 8){
					cst_descriptor[i].score_header = engine->score_header_buffer + offset_score_header;

					engine->cst_buffer[offset_cst].descriptor 	= cst_descriptor + i;
					engine->cst_buffer[offset_cst].score 		= engine->score_header_buffer + offset_score_header;
					engine->cst_buffer[offset_cst].score_offset = offset_score;
					engine->cst_buffer[offset_cst].size 		= cst_descriptor[i].nb_element * cst_descriptor[i].element_size;
					engine->cst_buffer[offset_cst].value 		= engine->value_buffer + offset_value;

					engine->score_header_buffer[offset_score_header].min_offset = 0xffffffffffffffff;
					engine->score_header_buffer[offset_score_header].max_offset = 0;
					engine->score_header_buffer[offset_score_header].score 		= engine->score_buffer + offset_score;

					memcpy(engine->value_buffer + offset_value, cst_descriptor[i].ptr, cst_descriptor[i].nb_element * cst_descriptor[i].element_size);

					offset_cst 				+= 1;
					offset_value 			+= cst_descriptor[i].nb_element * cst_descriptor[i].element_size;

					engine->cst_buffer[offset_cst].descriptor 	= cst_descriptor + i;
					engine->cst_buffer[offset_cst].score 		= engine->score_header_buffer + offset_score_header;
					engine->cst_buffer[offset_cst].score_offset = offset_score;
					engine->cst_buffer[offset_cst].size 		= cst_descriptor[i].nb_element * cst_descriptor[i].element_size;
					engine->cst_buffer[offset_cst].value 		= engine->value_buffer + offset_value;

					memcpy(engine->value_buffer + offset_value, cst_descriptor[i].ptr, cst_descriptor[i].nb_element * cst_descriptor[i].element_size);
					inv_endian(engine->value_buffer + offset_value, cst_descriptor[i].nb_element * cst_descriptor[i].element_size);


					offset_cst 				+= 1;
					offset_score_header 	+= 1;
					offset_value 			+= cst_descriptor[i].nb_element * cst_descriptor[i].element_size;
					offset_score 			+= 1;
				}
				else{
					log_warn_m("This case is not implemented yet, array of element of size %u", cst_descriptor[i].element_size);
				}
				break;
			}
			case CST_TYPE_LISTE : {
				if (cst_descriptor[i].element_size == 4){
					cst_descriptor[i].score_header = engine->score_header_buffer + offset_score_header;

					engine->score_header_buffer[offset_score_header].min_offset = 0xffffffffffffffff;
					engine->score_header_buffer[offset_score_header].max_offset = 0;
					engine->score_header_buffer[offset_score_header].score 		= engine->score_buffer + offset_score;

					for (j = 0; j  < cst_descriptor[i].nb_element; j++){
						engine->cst_buffer[offset_cst].descriptor 	= cst_descriptor + i;
						engine->cst_buffer[offset_cst].score 		= engine->score_header_buffer + offset_score_header;
						engine->cst_buffer[offset_cst].score_offset = offset_score;
						engine->cst_buffer[offset_cst].size 		= cst_descriptor[i].element_size;
						engine->cst_buffer[offset_cst].value 		= engine->value_buffer + offset_value;

						memcpy(engine->value_buffer + offset_value, cst_descriptor[i].ptr + j * cst_descriptor[i].element_size, cst_descriptor[i].element_size);

						offset_cst 				+= 1;
						offset_value 			+= cst_descriptor[i].element_size;

						engine->cst_buffer[offset_cst].descriptor 	= cst_descriptor + i;
						engine->cst_buffer[offset_cst].score 		= engine->score_header_buffer + offset_score_header;
						engine->cst_buffer[offset_cst].score_offset = offset_score;
						engine->cst_buffer[offset_cst].size 		= cst_descriptor[i].element_size;
						engine->cst_buffer[offset_cst].value 		= engine->value_buffer + offset_value;

						memcpy(engine->value_buffer + offset_value, cst_descriptor[i].ptr + j * cst_descriptor[i].element_size, cst_descriptor[i].element_size);
						inv_endian(engine->value_buffer + offset_value, cst_descriptor[i].element_size);

						offset_cst 				+= 1;
						offset_value 			+= cst_descriptor[i].element_size;
						offset_score 			+= 1;
					}
					offset_score_header 	+= 1;
				}
				else{
					log_warn_m("This case is not implemented yet, list of element of size %u", cst_descriptor[i].element_size);
				}
				break;
			}
			case CST_TYPE_INVALID 	: {
				goto next2;
			}
		}
	}

	next2:

	for (i = 0, offset_cst = 0; i < 256; i++){
		engine->accelerator[i].nb_cst = 0;
		engine->accelerator[i].offset = offset_cst;

		for (j = offset_cst; j < nb_cst; j++){
			if ((uint8_t)i == *(uint8_t*)(engine->cst_buffer[j].value)){
				if (j !=offset_cst){
					memcpy(&tmp, engine->cst_buffer + offset_cst, sizeof(struct cst));
					memcpy(engine->cst_buffer + offset_cst, engine->cst_buffer + j, sizeof(struct cst));
					memcpy(engine->cst_buffer + j, &tmp, sizeof(struct cst));
				}
				offset_cst ++;
			}
		}

		engine->accelerator[i].nb_cst = offset_cst - engine->accelerator[i].offset;
	}

	return 0;
}

static void searchCryptoCst_report_success(char* file_name, struct multiColumnPrinter* printer){
	uint32_t 	i;
	uint32_t 	j;
	uint8_t 	global_success;
	uint32_t 	local_success;
	char 		score_percent[32];

	for (i = 0, global_success = 0; ; i++){
		switch (cst_descriptor[i].type){
			case CST_TYPE_ARRAY : {
				if (cst_descriptor[i].score_header != NULL && *(cst_descriptor[i].score_header->score)){
					if (global_success){
						multiColumnPrinter_print(printer, "", cst_descriptor[i].name, "100%", cst_descriptor[i].score_header->min_offset,  cst_descriptor[i].score_header->max_offset, NULL);
					}
					else{
						global_success = 1;
						multiColumnPrinter_print(printer, file_name, cst_descriptor[i].name, "100%", cst_descriptor[i].score_header->min_offset,  cst_descriptor[i].score_header->max_offset, NULL);
					}
				}
				break;
			}
			case CST_TYPE_LISTE : {
				if (cst_descriptor[i].score_header != NULL){
					for (j = 0, local_success = 0; j < cst_descriptor[i].nb_element; j++){
						local_success += cst_descriptor[i].score_header->score[j];
					}

					if (local_success >= cst_descriptor[i].score_threshold){
						snprintf(score_percent, 32, "%u%%", (100 * local_success) / cst_descriptor[i].nb_element);
						if (global_success){
							multiColumnPrinter_print(printer, "", cst_descriptor[i].name, score_percent, cst_descriptor[i].score_header->min_offset,  cst_descriptor[i].score_header->max_offset, NULL);
						}
						else{
							global_success = 1;
							multiColumnPrinter_print(printer, file_name, cst_descriptor[i].name, score_percent, cst_descriptor[i].score_header->min_offset,  cst_descriptor[i].score_header->max_offset, NULL);
						}
					}
				}
				break;
			}
			case CST_TYPE_INVALID 	: {
				if (global_success){
					multiColumnPrinter_print_horizontal_separator(printer);
				}
				return;
			}
		}
	}
}