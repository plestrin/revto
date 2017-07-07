#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "util.h"
#include "multiColumn.h"

#ifdef ENABLE_AES
#include "key_aes.h"
#endif
#ifdef ENABLE_SERPENT
#include "key_serpent.h"
#endif
#ifdef ENABLE_DES
#include "key_des.h"
#endif
#ifdef ENABLE_TWOFISH
#include "key_twofish.h"
#endif
#ifdef ENABLE_SHA
#include "msg_sha.h"
#endif
#ifdef ENABLE_BER
#include "key_ber.h"
#endif

void(*key_handler_buffer[])(struct fileChunk*,struct multiColumnPrinter*) = {
	#ifdef ENABLE_AES
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
	#endif
	#ifdef ENABLE_SERPENT
	search_serpent_key,
	#endif
	#ifdef ENABLE_DES
	search_des_key,
	#endif
	#ifdef ENABLE_TWOFISH
	search_twofish_key,
	#endif
	#ifdef ENABLE_SHA
	search_sha1_msg,
	search_sha256_msg,
	search_sha512_msg,
	#endif
	#ifdef ENABLE_BER
	search_ber_key,
	#endif
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

	#ifdef ENABLE_AES
	if (init_aes_key){
		log_err("unable to init AES key");
		return EXIT_FAILURE;
	}
	#endif

	#ifdef ENABLE_SERPENT
	if (init_serpent_key){
		log_err("unable to init Serpent key");
		return EXIT_FAILURE;
	}
	#endif

	#ifdef ENABLE_DES
	if (init_des_key){
		log_err("unable to init DES key");
		return EXIT_FAILURE;
	}
	#endif

	#ifdef ENABLE_TWOFISH
	if (init_twofish_key){
		log_err("unable to init Twofish key");
		return EXIT_FAILURE;
	}
	#endif

	#ifdef ENABLE_SHA
	if (init_sha_msg){
		log_err("unable to init SHA msg");
		return EXIT_FAILURE;
	}
	#endif

	#ifdef ENABLE_BER
	if (init_ber_key){
		log_err("unable to init BER key");
		return EXIT_FAILURE;
	}
	#endif

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

	#ifdef ENABLE_AES
	clean_aes_key;
	#endif
	#ifdef ENABLE_SERPENT
	clean_serpent_key;
	#endif
	#ifdef ENABLE_DES
	clean_des_key;
	#endif
	#ifdef ENABLE_TWOFISH
	clean_twofish_key;
	#endif
	#ifdef ENABLE_SHA
	clean_sha_msg;
	#endif
	#ifdef ENABLE_BER
	clean_ber_key;
	#endif

	return EXIT_SUCCESS;
}
