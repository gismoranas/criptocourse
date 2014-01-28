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

#TODO move cyphertext to other file and read it, so it can be accidentally modified
#TODO make some order

def read_cyphertexts():
  cyphertexts_file = open('cyphertexts.txt', 'r')
  cyphertexts = cyphertexts_file.readlines()
  cyphertexts_file.close()
  return [ cyphertext.rstrip() for cyphertext in cyphertexts ]  

def xor_hexes_and_find_ascii_chars(index, cyphertexts):
  index_to_ascii_char_list = []
  cyphertext = cyphertexts[index]
  for i in range(len(cyphertexts)):
    if i == index:
      continue
    xored_hexes = xor_hexes(cyphertext, cyphertexts[i]).encode('hex')
    index_to_ascii_char_list.append(find_ascii_chars_in_hex(xored_hexes))
  return index_to_ascii_char_list

def find_most_probable_plaintext(index_to_ascii_char_list, plaintext_size):
  index_to_letters = defaultdict(list)
  for index_to_ascii_char in index_to_ascii_char_list:
    for index_1, ascii_char in index_to_ascii_char.iteritems():
      index_to_letters[index_1].append(ascii_char)
  plaintext = ['*']*plaintext_size
  for index_1, letters in index_to_letters.iteritems():    
    most_common = find_most_common_entries(letters)
    if most_common[1] > 2 and len(most_common[0]) == 1:
        plaintext[index_1] = most_common[0][0]
  return ''.join(plaintext)

def generate_key_from_noisy_plaintext_and_cyphertext(plaintext, cyphertext):
  key_with_noise = xor_string_hex(plaintext, cyphertext).encode('hex')
  key = ''
  for i in range(len(plaintext)):
    if plaintext[i] == '*':
      key += '*'
    else:
      key += key_with_noise[i*2:i*2+2]
  return key

def generate_noisy_key(index, cyphertexts):
  index_to_ascii_char_list = xor_hexes_and_find_ascii_chars(index, cyphertexts)
  plaintext = find_most_probable_plaintext(index_to_ascii_char_list, len(cyphertexts[index])/2)
  return generate_key_from_noisy_plaintext_and_cyphertext(plaintext, cyphertexts[index])

def find_most_probable_key(index_to_key_hexes):
  key = ['00']*(max(index_to_key_hexes.keys()) + 1)
  for index, hexes in index_to_key_hexes.iteritems():
    most_common = find_most_common_entries(hexes)
    if len(most_common[0]) > 1: 
      key[index] = '?'
    else:
      key[index] = most_common[0][0]  
  return ''.join(key)

def merge_noisy_keys(noisy_keys):
  keys = []
  index_to_key_hexes = defaultdict(list)
  for i in range(len(noisy_keys)):
    split_key = re.findall('\*|[0-9a-f]{2}', noisy_keys[i])
    for j in range(len(split_key)):
      if split_key[j] != '*':
        index_to_key_hexes[j].append(split_key[j])
  return find_most_probable_key(index_to_key_hexes)

def main():
  cyphertexts = read_cyphertexts()

  noisy_keys = []
  for i in range(len(cyphertexts)):
    noisy_keys.append(generate_noisy_key(i, cyphertexts))

  key = merge_noisy_keys(noisy_keys)

  print key

  for cyphertext in cyphertexts:
    print 'cyphertext', cyphertext[:10] 
    print 'xor', xor_hexes(cyphertext[:10], key)  

if __name__ == '__main__':
  main()
