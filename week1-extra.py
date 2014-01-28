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

def easy_decrypt(index, cyphertexts):
  cache = []
  chosen_cyphertext = cyphertexts[index]
  for i in range(11):
    if i == index:
      continue
    cache.append(find_space_indices_and_chars(chosen_cyphertext, cyphertexts[i]))
  index_to_letters = defaultdict(list)
  for cache_element in cache:
    for key in cache_element:
      index_to_letters[key].append(cache_element[key])
  plaintext = ['*']*(len(chosen_cyphertext)/2)
  for i, letters in index_to_letters.iteritems():    
    most_common = find_most_common_entries(letters)
    if most_common[1] > 2 and len(most_common[0]) == 1:
        plaintext[i] = most_common[0][0]

  plaintext = ''.join(plaintext)
  key = xor_string_hex(plaintext, chosen_cyphertext).encode('hex')
  key_as_string = ''
  for i in range(len(plaintext)):
    if plaintext[i] == '*':
      key_as_string += '*'
    else:
      key_as_string += key[i*2:i*2+2]
  return key_as_string

def merge_keys(index_to_hexes):
  key = ['00']*(max(index_to_hexes.keys()) + 1)
  for index, hexes in index_to_hexes.iteritems():
    most_common = find_most_common_entries(hexes)
    if len(most_common[0]) > 1: 
      key[index] = '?'
    else:
      key[index] = most_common[0][0]  
  return ''.join(key)
  

def main():
  keys = []
  index_to_hexes = defaultdict(list)
  cyphertexts = read_cyphertexts()
  for c in cyphertexts:
    print c
  for i in range(11):
    key = easy_decrypt(i, cyphertexts)
    split_key = re.findall('\*|[0-9a-f]{2}', key)
    for j in range(len(split_key)):
      if split_key[j] != '*':
        index_to_hexes[j].append(split_key[j])

  for index, hexes in index_to_hexes.iteritems():
    print index, hexes

  key = merge_keys(index_to_hexes)
  print key
  for cyphertext in cyphertexts:
    print 'cyphertext', cyphertext[:10] 
    print 'xor', xor_hexes(cyphertext[:10], key)  

if __name__ == '__main__':
  main()
