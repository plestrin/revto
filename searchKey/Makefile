EXE 	:= searchKey
CC		:= gcc
CFLAGS	:= -W -Wall -pedantic -Wextra -O3 -std=c99 -DSTEP_NB_BYTE=4

.PHONY: clean

all: build $(EXE)

build:
	mkdir -p build

$(EXE): build/searchCryptoKey.o build/util.o build/multiColumn.o build/key_aes.o build/key_serpent.o build/key_des.o build/key_twofish.o
	$(CC) -o $@ $^

build/%.o: src/%.c
	$(CC) -o $@ -c $< $(CFLAGS) -I../shared/

build/%.o: ../shared/%.c
	$(CC) -o $@ -c $< $(CFLAGS)
		
clean:
	@ rm -f *.o
	@ rm -f $(EXE)