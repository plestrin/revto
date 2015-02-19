EXE 	:= searchCst
CC		:= gcc
CFLAGS	:= -W -Wall -pedantic -Wextra -O3 -std=c99

.PHONY: clean

all: $(EXE)

$(EXE): build/searchCryptoCst.o build/util.o build/multiColumn.o build/cst.o
	$(CC) -o $@ $^

build/%.o: src/%.c
	$(CC) -o $@ -c $< $(CFLAGS) -I../shared/

build/%.o: ../shared/%.c
	$(CC) -o $@ -c $< $(CFLAGS)
		
clean:
	@ rm -f build/*.o
	@ rm -f $(EXE)