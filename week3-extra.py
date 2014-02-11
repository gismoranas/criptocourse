#!/usr/bin/python2.7 

import hashlib
import os

from collection_utils import *
from cripto_utils import *

def split_file(filename):
	data = []
	with open(filename, 'rb') as file_handle:
		chunk = file_handle.read(1024)
		while chunk != '':
			data.append(chunk)
			chunk = file_handle.read(1024)
	return data	

def hash_file(filename):
	data = split_file(filename)
	for i in range(len(data) - 1, 0, -1):
		if i != len(data) - 1:
			hash = hashlib.sha256(data[i] + previous_hash.hexdigest().decode('hex'))
		else:
			hash = hashlib.sha256(data[i]) 	
		previous_hash = hash
	return previous_hash	

def main():
	print hash_file('/home/cataldo/Downloads/test.mp4').hexdigest()

if __name__ == '__main__':
  main()
