#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "multiColumn.h"
#include "util.h"

static void multiColumnPrinter_constrain_string(const char* src, char* dst, size_t size);

struct multiColumnPrinter* multiColumnPrinter_create(FILE* file, uint32_t nb_column, uint32_t* sizes, enum multiColumnType* types, char* separator){
	struct multiColumnPrinter* 	printer;
	uint32_t 					i;

	if (!nb_column){
		log_warn("at least one column must be created");
		nb_column = 1;
	}

	if ((printer = malloc(sizeof(struct multiColumnPrinter) + (nb_column - 1) * sizeof(struct multiColumnColumn))) == NULL){
		log_err("unable to allocate memory");
		return NULL;
	}

	printer->file 		= file;
	printer->nb_column 	= nb_column;
	printer->flags 		= MPRINTER_FLAG_NEXT_SPE;

	printer->separator[sizeof printer->separator - 1] = 0;
	if (separator != NULL){
		strncpy(printer->separator, separator, sizeof printer->separator - 1);
	}
	else {
		strncpy(printer->separator, MULTICOLUMN_DEFAULT_SEPARATOR, sizeof printer->separator - 1);
	}

	for (i = 0; i < nb_column; i++){
		if (sizes != NULL){
			if (sizes[i] >= MULTICOLUMN_STRING_MAX_SIZE){
				log_warn_m("required size for column %u exceeds MULTICOLUMN_STRING_MAX_SIZE, please increment", i);
				printer->columns[i].size = MULTICOLUMN_STRING_MAX_SIZE - 1;
			}
			else {
				printer->columns[i].size = sizes[i];
			}
		}
		else {
			printer->columns[i].size = MULTICOLUMN_DEFAULT_SIZE;
		}
		if (types != NULL){
			if (MULTICOLUMN_TYPE_IS_VALID(types[i])){
				printer->columns[i].type = types[i];
			}
			else if (types[i] == MULTICOLUMN_TYPE_UNBOUND_STRING && i == nb_column - 1){
				printer->columns[i].type = types[i];
			}
			else {
				log_err_m("incorrect type value for column %u", i);
				printer->columns[i].type = MULTICOLUMN_DEFAULT_TYPE;
			}
		}
		else {
			printer->columns[i].type = MULTICOLUMN_DEFAULT_TYPE;
		}

		memset(printer->columns[i].title, '\0', MULTICOLUMN_STRING_MAX_SIZE);
		snprintf(printer->columns[i].title, MULTICOLUMN_STRING_MAX_SIZE, "TITLE %u", i);
	}

	return printer;
}

void multiColumnPrinter_set_column_size(struct multiColumnPrinter* printer, uint32_t column, uint32_t size){
	if (printer->nb_column > column){
		if (size >= MULTICOLUMN_STRING_MAX_SIZE){
			log_warn_m("required size for column %u exceeds MULTICOLUMN_STRING_MAX_SIZE, please increment", column);
			printer->columns[column].size = MULTICOLUMN_STRING_MAX_SIZE - 1;
		}
		else {
			printer->columns[column].size = size;
		}
	}
	else {
		log_err("column argument exceeds printer size");
	}
}

void multiColumnPrinter_set_column_type(struct multiColumnPrinter* printer, uint32_t column, enum multiColumnType type){
	if (printer->nb_column > column){
		if (MULTICOLUMN_TYPE_IS_VALID(type)){
			printer->columns[column].type = type;
		}
		else if (type == MULTICOLUMN_TYPE_UNBOUND_STRING && column == printer->nb_column - 1){
			printer->columns[column].type = type;
		}
		else {
			log_err("incorrect type value");
		}
	}
	else {
		log_err("column argument exceeds printer size");
	}
}

void multiColumnPrinter_set_title(struct multiColumnPrinter* printer, uint32_t column, const char* title){
	if (printer->nb_column > column){
		strncpy(printer->columns[column].title, title, MULTICOLUMN_STRING_MAX_SIZE - 1);
		printer->columns[column].title[MULTICOLUMN_STRING_MAX_SIZE - 1] = 0;
	}
	else {
		log_err("column argument exceeds printer size");
	}
}

void multiColumnPrinter_print_header(struct multiColumnPrinter* printer){
	char 		print_value[MULTICOLUMN_STRING_MAX_SIZE];
	uint32_t 	i;

	printer->flags &= ~MPRINTER_FLAG_AUTO_HDR;

	for (i = 0; i < printer->nb_column; i++){
		multiColumnPrinter_constrain_string(printer->columns[i].title, print_value, printer->columns[i].size);

		if (i == printer->nb_column - 1){
			fprintf(printer->file, "%s\n", print_value);
		}
		else {
			fprintf(printer->file, "%s%s", print_value, printer->separator);
		}
	}

	printer->flags |= MPRINTER_FLAG_NEXT_SPE;

	multiColumnPrinter_print_horizontal_separator(printer);
}

void multiColumnPrinter_print_horizontal_separator(struct multiColumnPrinter* printer){
	char 		print_value[MULTICOLUMN_STRING_MAX_SIZE];
	uint32_t	i;

	if (printer->flags & MPRINTER_FLAG_AUTO_HDR){
		multiColumnPrinter_print_header(printer);
	}

	if (printer->flags & MPRINTER_FLAG_NEXT_SPE){
		for (i = 0; i < printer->nb_column; i++){
			memset(print_value, '-', printer->columns[i].size);
			print_value[printer->columns[i].size] = '\0';

			if (i == printer->nb_column - 1){
				fprintf(printer->file, "%s\n", print_value);
			}
			else {
				fprintf(printer->file, "%s%s", print_value, printer->separator);
			}
		}
		printer->flags &= ~MPRINTER_FLAG_NEXT_SPE;
	}
}

void multiColumnPrinter_print(struct multiColumnPrinter* printer, ...){
	char* 		value_str = NULL;
	int8_t 		value_int8;
	int32_t 	value_int32;
	uint32_t 	value_uint32;
	uint64_t 	value_uint64;
	double		value_dbl;
	char 		print_value[MULTICOLUMN_STRING_MAX_SIZE];
	char 		raw_value[MULTICOLUMN_STRING_MAX_SIZE];
	va_list 	vl;
	uint32_t	i;

	if (printer->flags & MPRINTER_FLAG_AUTO_HDR){
		multiColumnPrinter_print_header(printer);
	}

	printer->flags |= MPRINTER_FLAG_NEXT_SPE;

	va_start(vl, printer);

	for (i = 0; i < printer->nb_column; i++){
		switch (printer->columns[i].type){
			case MULTICOLUMN_TYPE_STRING 	: {
				value_str = (char*)va_arg(vl, char*);
				break;
			}
			case MULTICOLUMN_TYPE_INT8 	: {
				value_str = raw_value;
				value_int8 = (int8_t)va_arg(vl, int32_t);
				snprintf(raw_value, MULTICOLUMN_STRING_MAX_SIZE, "%d", value_int8);
				break;
			}
			case MULTICOLUMN_TYPE_INT32 	: {
				value_str = raw_value;
				value_int32 = (int32_t)va_arg(vl, int32_t);
				snprintf(raw_value, MULTICOLUMN_STRING_MAX_SIZE, "%d", value_int32);
				break;
			}
			case MULTICOLUMN_TYPE_UINT32 	: {
				value_str = raw_value;
				value_uint32 = (uint32_t)va_arg(vl, uint32_t);
				snprintf(raw_value, MULTICOLUMN_STRING_MAX_SIZE, "%u", value_uint32);
				break;
			}
			case MULTICOLUMN_TYPE_DOUBLE 	: {
				value_str = raw_value;
				value_dbl = (double)va_arg(vl, double);
				snprintf(raw_value, MULTICOLUMN_STRING_MAX_SIZE, "%f", value_dbl);
				break;
			}
			case MULTICOLUMN_TYPE_HEX_32	: {
				value_str = raw_value;
				value_uint32 = (uint32_t)va_arg(vl, uint32_t);
				snprintf(raw_value, MULTICOLUMN_STRING_MAX_SIZE, "0x%08x", value_uint32);
				break;
			}
			case MULTICOLUMN_TYPE_HEX_64	: {
				value_str = raw_value;
				value_uint64 = (uint64_t)va_arg(vl, uint64_t);
				#ifdef __linux__
				#pragma GCC diagnostic ignored "-Wformat" /* ISO C90 does not support the ‘ll’ gnu_printf length modifier */
				snprintf(raw_value, MULTICOLUMN_STRING_MAX_SIZE, "0x%llx", value_uint64);
				#endif
				break;
			}
			case MULTICOLUMN_TYPE_UNBOUND_STRING 	: {
				value_str = (char*)va_arg(vl, char*);
				break;
			}
			case MULTICOLUMN_TYPE_BOOL 				: {
				if ((int32_t)va_arg(vl, int32_t)){
					value_str = "Y";
				}
				else {
					value_str = "N";
				}
				break;
			}
		}

		if (printer->columns[i].type != MULTICOLUMN_TYPE_UNBOUND_STRING){
			multiColumnPrinter_constrain_string(value_str, print_value, printer->columns[i].size);
		}

		if (i == printer->nb_column - 1){
			if (printer->columns[i].type == MULTICOLUMN_TYPE_UNBOUND_STRING){
				fprintf(printer->file, "%s\n", value_str);
			}
			else {
				fprintf(printer->file, "%s\n", print_value);
			}
		}
		else {
			fprintf(printer->file, "%s%s", print_value, printer->separator);
		}
	}

	va_end(vl);
}

void multiColumnPrinter_print_string_line(struct multiColumnPrinter* printer, const char* string, uint32_t string_size){
	char 		print_value[MULTICOLUMN_STRING_MAX_SIZE];
	uint32_t 	i;

	if (printer->flags & MPRINTER_FLAG_AUTO_HDR){
		multiColumnPrinter_print_header(printer);
		printer->flags &= ~MPRINTER_FLAG_AUTO_HDR;
	}

	printer->flags |= MPRINTER_FLAG_NEXT_SPE;

	fputc('\r', printer->file);

	for (i = 0; i < printer->nb_column; i++){
		multiColumnPrinter_constrain_string(string + (i * string_size), print_value, printer->columns[i].size);

		if (i == printer->nb_column - 1){
			fputs(print_value, printer->file);
		}
		else {
			fprintf(printer->file, "%s%s", print_value, printer->separator);
		}
	}
	fflush(printer->file);
}

static void multiColumnPrinter_constrain_string(const char* src, char* dst, size_t size){
	size_t length;

	strncpy(dst, src, size);
	length = strlen(src);
	dst[size] = '\0';
	if (length > size){
		if (size >= 3){
			dst[size - 3] = '.';
		}
		if (size >= 2){
			dst[size - 2] = '.';
		}
		if (size >= 1){
			dst[size - 1] = '.';
		}
	}
	else {
		memset(dst + length, ' ', size - length);
	}
}
