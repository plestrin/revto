EXE 	:= searchKey
CC		:= gcc
CFLAGS	:= -W -Wall -pedantic -Wextra -O3 -std=c99 -DSTEP_NB_BYTE=4 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
OBJ 	:= searchCryptoKey.o util.o multiColumn.o

ENABLE_DEFAULT_AES 		:= 1
ENABLE_DEFAULT_SERPENT 	:= 1
ENABLE_DEFAULT_DES 		:= 0
ENABLE_DEFAULT_TWOFISH 	:= 0
ENABLE_DEFAULT_SHA 		:= 1
ENABLE_DEFAULT_BER 		:= 1
ENABLE_DEFAULT_PEM 		:= 1
ENABLE_DEFAULT_OPENSSH 	:= 1
ENABLE_DEFAULT_PUB 		:= 1

THROUGHPUT_AES 		:= 5.37 MBytes/s
THROUGHPUT_SERPENT 	:= 100  MBytes/s
THROUGHPUT_DES 		:= 1.54 MBytes/s
THROUGHPUT_TWOFISH 	:= 6.16 KBytes/s
THROUGHPUT_SHA 		:= 50.0 MBytes/s
THROUGHPUT_BER 		:= 107  MBytes/s
THROUGHPUT_PEM 		:= ??   MBytes/s
THROUGHPUT_OPENSSH  := ??   MBytes/s

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

ifeq ($(ENABLE_PEM),)
	ENABLE_PEM := $(ENABLE_DEFAULT_PEM)
endif
ifeq ($(ENABLE_PEM),1)
	OBJ 	:= $(OBJ) key_pem.o
	CFLAGS 	:= $(CFLAGS) -DENABLE_PEM
	ifeq ($(ENABLE_BER),0)
		OBJ := $(OBJ) key_ber.o
	endif
endif

ifeq ($(ENABLE_OPENSSH),)
	ENABLE_OPENSSH := $(ENABLE_DEFAULT_OPENSSH)
endif
ifeq ($(ENABLE_OPENSSH),1)
	OBJ 	:= $(OBJ) key_openssh.o
	CFLAGS 	:= $(CFLAGS) -DENABLE_OPENSSH
endif

ifeq ($(ENABLE_PUB),)
	ENABLE_PUB := $(ENABLE_DEFAULT_PUB)
endif
ifeq ($(ENABLE_PUB),1)
	CFLAGS 	:= $(CFLAGS) -DENABLE_PUB
endif

.PHONY: clean

all: build $(EXE)
	@ echo "**************** BUILD SUMMARY ****************"
	@ echo "Algorithm     | Enabled | Indicative Throughput"
	@ echo "--------------|---------|----------------------"
ifeq ($(ENABLE_AES),1)
	@ echo "AES           | yes     | $(THROUGHPUT_AES)"
else
	@ echo "AES           | no      | $(THROUGHPUT_AES)"
endif
ifeq ($(ENABLE_SERPENT),1)
	@ echo "SERPENT       | yes     | $(THROUGHPUT_SERPENT)"
else
	@ echo "SERPENT       | no      | $(THROUGHPUT_SERPENT)"
endif
ifeq ($(ENABLE_DES),1)
	@ echo "DES           | yes     | $(THROUGHPUT_DES)"
else
	@ echo "DES           | no      | $(THROUGHPUT_DES)"
endif
ifeq ($(ENABLE_TWOFISH),1)
	@ echo "TWOFISH       | yes     | $(THROUGHPUT_TWOFISH)"
else
	@ echo "TWOFISH       | no      | $(THROUGHPUT_TWOFISH)"
endif
ifeq ($(ENABLE_SHA),1)
	@ echo "SHA           | yes     | $(THROUGHPUT_SHA)"
else
	@ echo "SHA           | no      | $(THROUGHPUT_SHA)"
endif
ifeq ($(ENABLE_BER),1)
	@ echo "BER           | yes     | $(THROUGHPUT_BER)"
else
	@ echo "BER           | no      | $(THROUGHPUT_BER)"
endif
ifeq ($(ENABLE_PEM),1)
	@ echo "PEM           | yes     | $(THROUGHPUT_PEM)"
else
	@ echo "PEM           | no      | $(THROUGHPUT_PEM)"
endif
ifeq ($(ENABLE_OPENSSH),1)
	@ echo "OPENSSH       | yes     | $(THROUGHPUT_OPENSSH)"
else
	@ echo "OPENSSH       | no      | $(THROUGHPUT_OPENSSH)"
endif
ifeq ($(ENABLE_PUB),1)
	@ echo "Public key(s) will be reported!"
else
	@ echo "Public key(s) will not be reported!"
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
