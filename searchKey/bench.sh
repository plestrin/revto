#!/bin/sh

PARSER_SCRIPT="
import sys

f = open(sys.argv[1], 'r')
lines = f.readlines()
f.close()

if len(lines) != 6:
	print 'Error: missing entries cannot parse'
	exit(0)

print 'AES:     ' + str(round(16 / float(lines[0][:-1]), 2)) + ' MBytes/s'
print 'SERPENT: ' + str(round(16 / float(lines[1][:-1]), 2)) + ' MBytes/s'
print 'DES:     ' + str(round(16 / float(lines[2][:-1]), 2)) + ' MBytes/s'
print 'TWOFISH: ' + str(round(256 / float(lines[3][:-1]), 2)) + ' KBytes/s'
print 'SHA:     ' + str(round(16 / float(lines[4][:-1]), 2)) + ' MBytes/s'
print 'BER:     ' + str(round(16 / float(lines[5][:-1]), 2)) + ' MBytes/s'
"

echo "Warning: you'll probably have to recompile the program with your own configuration afterwards."

TEMP_FILE=$(mktemp)

# AES
make clean >> /dev/null
make ENABLE_AES=1 ENABLE_SERPENT=0 ENABLE_DES=0 ENABLE_TWOFISH=0 ENABLE_SHA=0 ENABLE_BER=0 ENABLE_PEM=0 >> /dev/null
dd if=/dev/urandom bs=65536 count=256 status=none | time -f "%e" -o $TEMP_FILE --append ./searchKey >> /dev/null

# SERPENT
make clean >> /dev/null
make ENABLE_AES=0 ENABLE_SERPENT=1 ENABLE_DES=0 ENABLE_TWOFISH=0 ENABLE_SHA=0 ENABLE_BER=0 ENABLE_PEM=0 >> /dev/null
dd if=/dev/urandom bs=65536 count=256 status=none | time -f "%e" -o $TEMP_FILE --append ./searchKey >> /dev/null

# DES
make clean >> /dev/null
make ENABLE_AES=0 ENABLE_SERPENT=0 ENABLE_DES=1 ENABLE_TWOFISH=0 ENABLE_SHA=0 ENABLE_BER=0 ENABLE_PEM=0 >> /dev/null
dd if=/dev/urandom bs=65536 count=256 status=none | time -f "%e" -o $TEMP_FILE --append ./searchKey >> /dev/null

# TWOFISH
make clean >> /dev/null
make ENABLE_AES=0 ENABLE_SERPENT=0 ENABLE_DES=0 ENABLE_TWOFISH=1 ENABLE_SHA=0 ENABLE_BER=0 ENABLE_PEM=0 >> /dev/null
dd if=/dev/urandom bs=65536 count=4 status=none | time -f "%e" -o $TEMP_FILE --append ./searchKey >> /dev/null

# SHA
make clean >> /dev/null
make ENABLE_AES=0 ENABLE_SERPENT=0 ENABLE_DES=0 ENABLE_TWOFISH=0 ENABLE_SHA=1 ENABLE_BER=0 ENABLE_PEM=0 >> /dev/null
dd if=/dev/urandom bs=65536 count=256 status=none | time -f "%e" -o $TEMP_FILE --append ./searchKey >> /dev/null

# BER
make clean >> /dev/null
make ENABLE_AES=0 ENABLE_SERPENT=0 ENABLE_DES=0 ENABLE_TWOFISH=0 ENABLE_SHA=0 ENABLE_BER=1 ENABLE_PEM=0 >> /dev/null
dd if=/dev/urandom bs=65536 count=256 status=none | time -f "%e" -o $TEMP_FILE --append ./searchKey >> /dev/null

python -c "$PARSER_SCRIPT" $TEMP_FILE

rm $TEMP_FILE
