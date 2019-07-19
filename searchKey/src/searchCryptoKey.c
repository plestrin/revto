#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "searchCryptoKey.h"
#include "util.h"

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

	if ((printer = multiColumnPrinter_create(stdout, (argc > 2) ? 6 : 5, NULL, NULL, NULL)) == NULL){
		log_err("Unable to create multiColumn printer");
	}
	else{

		i = 0;
		if (argc > 2){
			multiColumnPrinter_set_column_size(printer, 0, 64);
			multiColumnPrinter_set_title(printer, 0, "FILE");
			i ++;
		}

		multiColumnPrinter_set_column_size(printer, i + 0, 12);
		multiColumnPrinter_set_column_size(printer, i + 1, 6);
		multiColumnPrinter_set_column_size(printer, i + 2, 7);
		multiColumnPrinter_set_column_size(printer, i + 3, 12);
		multiColumnPrinter_set_column_size(printer, i + 4, 32);

		multiColumnPrinter_set_column_type(printer, i + 3, MULTICOLUMN_TYPE_HEX_64);
		multiColumnPrinter_set_column_type(printer, i + 4, MULTICOLUMN_TYPE_UNBOUND_STRING);

		multiColumnPrinter_set_title(printer, i + 0, "NAME");
		multiColumnPrinter_set_title(printer, i + 1, "ENDIAN");
		multiColumnPrinter_set_title(printer, i + 2, "DEC-ENC");
		multiColumnPrinter_set_title(printer, i + 3, "OFFSET");
		multiColumnPrinter_set_title(printer, i + 4, "KEY/MSG");

		printer->flags &= MPRINTER_FLAG_AUTO_HDR;

		if (argc > 1){
			for (i = 1; i < argc; i++){
				if (fileChunk_open(&chunk, argv[i])){
					log_err("Unable to get first file chunk");
					continue;
				}

				while (fileChunk_get_next(&chunk)){
					for (j = 0; key_handler_buffer[j] != NULL; j++){
						key_handler_buffer[j](&chunk, printer);
					}
				}

				fileChunk_close(chunk);
				fileChunk_clean(chunk)
			}
		}
		else{
			fileChunk_init(chunk, stdin, NULL)

			while (fileChunk_get_next(&chunk)){
				for (j = 0; key_handler_buffer[j] != NULL; j++){
					key_handler_buffer[j](&chunk, printer);
				}
			}

			fileChunk_clean(chunk)
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

void searchCryptoKey_report_success(const char* buffer, size_t size, off_t offset, enum endianness endian, const char* name, const char* enc_dec_desc, const char* file_name, struct multiColumnPrinter* printer){
	char* data_str;

	data_str = alloca(2 * size + 1);

	if (endian == _BIG_ENDIAN){
		sprintBuffer_raw_inv_endian(data_str, buffer, size);
	}
	else{
		sprintBuffer_raw(data_str, buffer, size);
	}
	if (file_name == NULL || printer->nb_column == 5){
		multiColumnPrinter_print(printer, name, (endian == _BIG_ENDIAN) ? "b" : "c", enc_dec_desc, offset, data_str);
	}
	else{
		multiColumnPrinter_print(printer, file_name, name, (endian == _BIG_ENDIAN) ? "b" : "c", enc_dec_desc, offset, data_str);
	}
}
