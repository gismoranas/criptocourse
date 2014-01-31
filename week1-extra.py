#!/usr/bin/python 

import collections
import itertools
import re
import sys

from collections import defaultdict
from operator import itemgetter

from collection_utils import *
from crypto_utils import *
from xor_utils import * 

#TODO move ciphertext to other file and read it, so it can be accidentally modified

def read_ciphertexts():
  ciphertexts_file = open('ciphertexts.txt', 'r')
  ciphertexts = ciphertexts_file.readlines()
  ciphertexts_file.close()
  return [ ciphertext.rstrip() for ciphertext in ciphertexts ]  

def find_xored_plaintexts_list(index, ciphertexts):
  xored_plaintexts_list = []
  for i in range(10):
    if i == index:
      xored_plaintexts_list.append('') 
    else:
      xored_hexes = xor_hexes(ciphertexts[index], ciphertexts[i]).encode('hex')    
      xored_plaintexts_list.append(''.join(hex_to_ascii_char(xored_hexes)).swapcase())
  return xored_plaintexts_list

def find_space_indices(xored_plaintexts_list, tolerance):
  min_len = sorted([ len(i) for i in xored_plaintexts_list ])[1]
  space_indices = []
  for i in range(min_len):
    column = [ xored_plaintext[i] for xored_plaintext in xored_plaintexts_list if xored_plaintext != '']
    is_column_space = reduce(lambda x, y : x + (y == '_' or str.isalpha(y)), column, 0) >= len(column) - tolerance   
    if is_column_space:
      space_indices.append(i) 
  return space_indices

def guess_cyphertext(index, ciphertexts, plaintexts):
  xored_plaintexts_list = find_xored_plaintexts_list(index, ciphertexts)
  space_indices = find_space_indices(xored_plaintexts_list, 1)
  for i, xored_plaintexts in enumerate(xored_plaintexts_list):
    if i == index:
      plaintexts[i].extend([ (space_index, '_') for space_index in space_indices]) 
    else:
      plaintexts[i].extend([ (space_index, xored_plaintexts[space_index]) for space_index in space_indices ])

def print_plaintexts(plaintexts):
  for i in range(len(plaintexts)):
    clean_plaintext = sorted(set(plaintexts[i]))
    length = clean_plaintext[-1][0] + 1
    plaintext = ['*']*length
    for j in range(length):
      chars_at_j = [ k[1] for k in clean_plaintext if k[0] == j ]  
      if len(chars_at_j) == 1:
        plaintext[j] = chars_at_j[0]
      elif len(chars_at_j) > 1:
        plaintext[j] = '?'
    print i, ''.join(plaintext)

def main():  
  ciphertexts = read_ciphertexts()
  secret_ciphertext = ciphertexts[-1]
  ciphertexts = ciphertexts[:-1]

  plaintexts = defaultdict(list) 

  for i in range(10):
    guess_cyphertext(i, ciphertexts, plaintexts)
  
  print_plaintexts(plaintexts)

  key = xor_string_hex('The ciphertext produced by a weak encryption algorithm looks as good as ciphertext produced by ', ciphertexts[3])
  for ciphertext in ciphertexts:
    print xor_string_hex(key, ciphertext)
  solution = xor_string_hex(key, secret_ciphertext)
  print '--', solution, '--'

if __name__ == '__main__':
  main()
