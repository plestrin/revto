#!/bin/sh

AES_LOAD=16
SERPENT_LOAD=256
DES_LOAD=8
TWOFISH_LOAD=64
SHA_LOAD=128
BER_LOAD=512
PEM_LOAD=512
OPENSSL_LOAD=512

BS_MB=1048576
BS_KB=1024

PARSER_SCRIPT="
import sys

def print_result(name, time, size, unit):
	print('%-7s: %.2f s, %.2f %s/s' % (name, round(time, 2), round(size / time, 2), unit))

with open(sys.argv[1], 'r') as f:
	times = [float(line.strip()) for line in f.readlines()]

if len(times) != 8:
	print('Error: missing entries cannot parse')
else:
	print_result('AES', times[0], $AES_LOAD, 'MBytes')
	print_result('SERPENT', times[1], $SERPENT_LOAD, 'MBytes')
	print_result('DES', times[2], $DES_LOAD, 'MBytes')
	print_result('TWOFISH', times[3], $TWOFISH_LOAD, 'KBytes')
	print_result('SHA', times[4], $SHA_LOAD, 'MBytes')
	print_result('BER', times[5], $BER_LOAD, 'MBytes')
	print_result('PEM', times[6], $PEM_LOAD, 'MBytes')
	print_result('OPENSSL', times[7], $OPENSSL_LOAD, 'MBytes')
"

echo "Warning: you'll probably have to recompile the program with your own configuration afterwards."

TEMP_FILE=$(mktemp)

# AES
make clean >> /dev/null
make ENABLE_PUB=1 ENABLE_AES=1 ENABLE_SERPENT=0 ENABLE_DES=0 ENABLE_TWOFISH=0 ENABLE_SHA=0 ENABLE_BER=0 ENABLE_PEM=0 ENABLE_OPENSSH=0 >> /dev/null
dd if=/dev/urandom bs=$BS_MB count=$AES_LOAD status=none | /usr/bin/time -f "%e" -o "$TEMP_FILE" --append ./searchKey >> /dev/null

# SERPENT
make clean >> /dev/null
make ENABLE_PUB=1 ENABLE_AES=0 ENABLE_SERPENT=1 ENABLE_DES=0 ENABLE_TWOFISH=0 ENABLE_SHA=0 ENABLE_BER=0 ENABLE_PEM=0 ENABLE_OPENSSH=0 >> /dev/null
dd if=/dev/urandom bs=$BS_MB count=$SERPENT_LOAD status=none | /usr/bin/time -f "%e" -o "$TEMP_FILE" --append ./searchKey >> /dev/null

# DES
make clean >> /dev/null
make ENABLE_PUB=1 ENABLE_AES=0 ENABLE_SERPENT=0 ENABLE_DES=1 ENABLE_TWOFISH=0 ENABLE_SHA=0 ENABLE_BER=0 ENABLE_PEM=0 ENABLE_OPENSSH=0 >> /dev/null
dd if=/dev/urandom bs=$BS_MB count=$DES_LOAD status=none | /usr/bin/time -f "%e" -o "$TEMP_FILE" --append ./searchKey >> /dev/null

# TWOFISH
make clean >> /dev/null
make ENABLE_PUB=1 ENABLE_AES=0 ENABLE_SERPENT=0 ENABLE_DES=0 ENABLE_TWOFISH=1 ENABLE_SHA=0 ENABLE_BER=0 ENABLE_PEM=0 ENABLE_OPENSSH=0 >> /dev/null
dd if=/dev/urandom bs=$BS_KB count=$TWOFISH_LOAD status=none | /usr/bin/time -f "%e" -o "$TEMP_FILE" --append ./searchKey >> /dev/null

# SHA
make clean >> /dev/null
make ENABLE_PUB=1 ENABLE_AES=0 ENABLE_SERPENT=0 ENABLE_DES=0 ENABLE_TWOFISH=0 ENABLE_SHA=1 ENABLE_BER=0 ENABLE_PEM=0 ENABLE_OPENSSH=0 >> /dev/null
dd if=/dev/urandom bs=$BS_MB count=$SHA_LOAD status=none | /usr/bin/time -f "%e" -o "$TEMP_FILE" --append ./searchKey >> /dev/null

# BER
make clean >> /dev/null
make ENABLE_PUB=1 ENABLE_AES=0 ENABLE_SERPENT=0 ENABLE_DES=0 ENABLE_TWOFISH=0 ENABLE_SHA=0 ENABLE_BER=1 ENABLE_PEM=0 ENABLE_OPENSSH=0 >> /dev/null
dd if=/dev/urandom bs=$BS_MB count=$BER_LOAD status=none | /usr/bin/time -f "%e" -o "$TEMP_FILE" --append ./searchKey >> /dev/null

# PEM
make clean >> /dev/null
make ENABLE_PUB=1 ENABLE_AES=0 ENABLE_SERPENT=0 ENABLE_DES=0 ENABLE_TWOFISH=0 ENABLE_SHA=0 ENABLE_BER=0 ENABLE_PEM=1 ENABLE_OPENSSH=0 >> /dev/null
dd if=/dev/urandom bs=$BS_MB count=$PEM_LOAD status=none | /usr/bin/time -f "%e" -o "$TEMP_FILE" --append ./searchKey >> /dev/null

# OPENSSL
make clean >> /dev/null
make ENABLE_PUB=1 ENABLE_AES=0 ENABLE_SERPENT=0 ENABLE_DES=0 ENABLE_TWOFISH=0 ENABLE_SHA=0 ENABLE_BER=0 ENABLE_PEM=0 ENABLE_OPENSSH=1 >> /dev/null
dd if=/dev/urandom bs=$BS_MB count=$OPENSSL_LOAD status=none | /usr/bin/time -f "%e" -o "$TEMP_FILE" --append ./searchKey >> /dev/null

python -c "$PARSER_SCRIPT" "$TEMP_FILE"

rm "$TEMP_FILE"
