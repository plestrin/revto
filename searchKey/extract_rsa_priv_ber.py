#!/usr/bin/python

import sys
import os
import struct
import hashlib
import argparse

def check(data):
	# Modulus
	offset = 9
	if offset + 2 > len(data):
		return False
	mod_size = struct.unpack('>H', data[offset: offset + 2])[0]
	offset += 2
	if offset + mod_size > len(data):
		return False
	offset += mod_size

	# Public Exponent
	if offset + 2 > len(data):
		return False
	if data[offset] != '\x02' and ord(data[offset + 1]) & 0x80:
		return False
	pri_size = ord(data[offset + 1])
	offset += 2
	if offset + pri_size > len(data):
		return False
	offset += pri_size

	# Private Exponent
	if offset + 4 > len(data):
		return False
	if data[offset: offset + 2] != '\x02\x82':
		return False
	pri_size = struct.unpack('>H', data[offset + 2: offset + 4])[0]
	offset += 2
	if offset + pri_size > len(data):
		return False

	# Other fields are not checked ...

	return True

def get_modulus(data):
	size =  struct.unpack('>H', data[9:11])[0]
	return data[11: 11 + size]

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Extract BER encoded RSA private keys from binary files')

	parser.add_argument('-o', '--output', default=False, help='Output directory', dest='out')
	parser.add_argument('files', nargs='+', help='binary files')

	args = parser.parse_args()

	name_set = set()

	for file_name in args.files:
		f = open(file_name, 'rb')
		d = f.read()
		f.close()

		nb = 0

		strt = d.find('\x30\x82')
		while strt != -1 and strt + 11 <= len(d):
			if d[strt + 4: strt + 6] == '\x02\x01' and d[strt + 7: strt + 9] == '\x02\x82':
				size = struct.unpack('>H', d[strt + 2: strt + 4])[0]
				if strt + size <= len(d):
					key = d[strt: strt + size + 4]
					if check(key):
						h = hashlib.new('sha256')
						h.update(get_modulus(key))
						name = h.hexdigest()

						if not name in name_set:
							if args.out:
								out_file_name = os.path.join(args.out, name + '.key')
							else:
								out_file_name = name + '.key'

							f = open(out_file_name, 'wb')
							f.write(key)
							f.close()

							nb += 1
							name_set.add(name)

			strt = d.find('\x30\x82', strt + 1)

		if nb:
			sys.stderr.write('\x1b[32m[+]\x1b[0m ' + str(nb) + ' RSA private key have been found in ' + file_name + '\n')
		else:
			sys.stderr.write('\x1b[31m[!]\x1b[0m no RSA private key in ' + file_name + '\n')
