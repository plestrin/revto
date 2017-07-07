EXE 	:= searchKey
CC		:= gcc
CFLAGS	:= -W -Wall -pedantic -Wextra -O3 -std=c99 -DSTEP_NB_BYTE=4 -DFILECHUNCK_OVERLAP=102400 -DFILECHUNCK_MAX_LENGTH=40960000
OBJ 	:= searchCryptoKey.o util.o multiColumn.o

ENABLE_DEFAULT_AES 		:= 1
ENABLE_DEFAULT_SERPENT 	:= 1
ENABLE_DEFAULT_DES 		:= 0
ENABLE_DEFAULT_TWOFISH 	:= 0
ENABLE_DEFAULT_SHA 		:= 1
ENABLE_DEFAULT_BER 		:= 1

ifeq ($(ENABLE_AES),)
	ENABLE_AES := $(ENABLE_DEFAULT_AES)
endif
ifeq ($(ENABLE_AES),1)
	OBJ 	:= $(OBJ) key_aes.o
	CFLAGS 	:= $(CFLAGS) -DENABLE_AES
endif

ifeq ($(ENABLE_SERPENT),)
	ENABLE_SERPENT := $(ENABLE_DEFAULT_SERPENT)
endif
ifeq ($(ENABLE_SERPENT),1)
	OBJ 	:= $(OBJ) key_serpent.o
	CFLAGS 	:= $(CFLAGS) -DENABLE_SERPENT
endif

ifeq ($(ENABLE_DES),)
	ENABLE_DES := $(ENABLE_DEFAULT_DES)
endif
ifeq ($(ENABLE_DES),1)
	OBJ 	:= $(OBJ) key_des.o
	CFLAGS 	:= $(CFLAGS) -DENABLE_DES
endif

ifeq ($(ENABLE_TWOFISH),)
	ENABLE_TWOFISH := $(ENABLE_DEFAULT_TWOFISH)
endif
ifeq ($(ENABLE_TWOFISH),1)
	OBJ 	:= $(OBJ) key_twofish.o
	CFLAGS 	:= $(CFLAGS) -DENABLE_TWOFISH
endif

ifeq ($(ENABLE_SHA),)
	ENABLE_SHA := $(ENABLE_DEFAULT_SHA)
endif
ifeq ($(ENABLE_SHA),1)
	OBJ 	:= $(OBJ) msg_sha.o
	CFLAGS 	:= $(CFLAGS) -DENABLE_SHA
endif

ifeq ($(ENABLE_BER),)
	ENABLE_BER := $(ENABLE_DEFAULT_BER)
endif
ifeq ($(ENABLE_BER),1)
	OBJ 	:= $(OBJ) key_ber.o
	CFLAGS 	:= $(CFLAGS) -DENABLE_BER
endif

.PHONY: clean

all: build $(EXE)
	@ echo "**************** BUILD SUMMARY ****************"
	@ echo "Algorithm     | Enabled | Indicative Throughput"
	@ echo "--------------|---------|----------------------"
ifeq ($(ENABLE_AES),1)
	@ echo "AES           | yes     | ??"
else
	@ echo "AES           | no      | ??"
endif
ifeq ($(ENABLE_SERPENT),1)
	@ echo "SERPENT       | yes     | ??"
else
	@ echo "SERPENT       | no      | ??"
endif
ifeq ($(ENABLE_DES),1)
	@ echo "DES           | yes     | ??"
else
	@ echo "DES           | no      | ??"
endif
ifeq ($(ENABLE_TWOFISH),1)
	@ echo "TWOFISH       | yes     | ??"
else
	@ echo "TWOFISH       | no      | ??"
endif
ifeq ($(ENABLE_SHA),1)
	@ echo "SHA           | yes     | ??"
else
	@ echo "SHA           | no      | ??"
endif
ifeq ($(ENABLE_BER),1)
	@ echo "BER           | yes     | ??"
else
	@ echo "BER           | no      | ??"
endif

build:
	mkdir -p build

$(EXE): $(foreach obj,$(OBJ),build/$(obj))
	$(CC) -o $@ $^

build/%.o: src/%.c
	$(CC) -o $@ -c $< $(CFLAGS) -I../shared/

build/%.o: ../shared/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	@ rm -rf build
	@ rm -f $(EXE)
