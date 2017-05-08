#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "util.h"
#include "multiColumn.h"

#include "key_aes.h"
#include "key_serpent.h"
#include "key_des.h"
#include "key_twofish.h"
#include "msg_sha.h"
#include "key_ber.h"

void(*key_handler_buffer[])(struct fileChunk*,struct multiColumnPrinter*) = {
	search_AES128_enc_key_big_endian,
	search_AES128_dec_key_big_endian,
	search_AES128_enc_key_little_endian,
	search_AES128_dec_key_little_endian,
	search_AES192_enc_key_big_endian,
	search_AES192_dec_key_big_endian,
	search_AES192_enc_key_little_endian,
	search_AES192_dec_key_little_endian,
	search_AES256_enc_key_big_endian,
	search_AES256_dec_key_big_endian,
	search_AES256_enc_key_little_endian,
	search_AES256_dec_key_little_endian,
	search_serpent_key,
	/*search_des_key, 	*/						/* SLOW - comment if it takes too long */
	/*search_twofish_key,*/ 					/* SLOW - comment if it takes too long */
	search_sha1_msg,
	search_sha256_msg,
	search_sha512_msg,
	search_ber_key,
	NULL
};

int32_t main(int32_t argc, char** argv){
	struct fileChunk 			chunk;
	int32_t 					i;
	uint32_t 					j;
	struct multiColumnPrinter* 	printer;

	if (argc < 2){
		log_err("Please specify a binary file");
		return EXIT_FAILURE;
	}

	if (init_aes_key){
		log_err("unable to init AES key");
		return EXIT_FAILURE;
	}
	if (init_serpent_key){
		log_err("unable to init Serpent key");
		return EXIT_FAILURE;
	}
	if (init_des_key){
		log_err("unable to init DES key");
		return EXIT_FAILURE;
	}
	if (init_twofish_key){
		log_err("unable to init Twofish key");
		return EXIT_FAILURE;
	}
	if (init_sha_msg){
		log_err("unable to init SHA msg");
		return EXIT_FAILURE;
	}
	if (init_ber_key){
		log_err("unable to init BER key");
		return EXIT_FAILURE;
	}

	printer = multiColumnPrinter_create(stdout, 6, NULL, NULL, NULL);
	if (printer == NULL){
		log_err("Unable to create multiColumn printer");
	}
	else{
		multiColumnPrinter_set_column_size(printer, 0, 64);
		multiColumnPrinter_set_column_size(printer, 1, 12);
		multiColumnPrinter_set_column_size(printer, 2, 6);
		multiColumnPrinter_set_column_size(printer, 3, 7);
		multiColumnPrinter_set_column_size(printer, 4, 12);

		multiColumnPrinter_set_column_type(printer, 4, MULTICOLUMN_TYPE_HEX_64);
		multiColumnPrinter_set_column_type(printer, 5, MULTICOLUMN_TYPE_UNBOUND_STRING);

		multiColumnPrinter_set_title(printer, 0, "FILE");
		multiColumnPrinter_set_title(printer, 1, "NAME");
		multiColumnPrinter_set_title(printer, 2, "ENDIAN");
		multiColumnPrinter_set_title(printer, 3, "DEC-ENC");
		multiColumnPrinter_set_title(printer, 4, "OFFSET");
		multiColumnPrinter_set_title(printer, 5, "KEY/MSG");

		multiColumnPrinter_print_header(printer);


		for (i = 1; i < argc; i++){
			fileChunk_init(chunk, argv[i]);
			while (!fileChunk_get_next(&chunk)){
				for (j = 0; key_handler_buffer[j] != NULL; j++){
					key_handler_buffer[j](&chunk, printer);
				}
			}
		}

		multiColumnPrinter_delete(printer);
	}

	clean_aes_key;
	clean_serpent_key;
	clean_des_key;
	clean_twofish_key;
	clean_sha_msg;
	clean_ber_key;

	return EXIT_SUCCESS;
}
