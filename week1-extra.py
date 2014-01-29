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
#TODO make some order

def read_ciphertexts():
  ciphertexts_file = open('ciphertexts.txt', 'r')
  ciphertexts = ciphertexts_file.readlines()
  ciphertexts_file.close()
  return [ ciphertext.rstrip() for ciphertext in ciphertexts ]  

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

def generate_key_from_noisy_plaintext_and_ciphertext(plaintext, ciphertext):
  key_with_noise = xor_string_hex(plaintext, ciphertext).encode('hex')
  key = ''
  for i in range(len(plaintext)):
    if plaintext[i] == '*':
      key += '*'
    else:
      key += key_with_noise[i*2:i*2+2]
  return key

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
  return ''.join(plaintext).swapcase()

def xor_hexes_and_find_ascii_chars(index, ciphertexts):
  index_to_ascii_char_list = []
  ciphertext = ciphertexts[index]
  for i in range(len(ciphertexts)):
    if i == index:
      continue
    xored_hexes = xor_hexes(ciphertext, ciphertexts[i]).encode('hex')
    index_to_ascii_char_list.append(find_ascii_chars_in_hex(xored_hexes))
  return index_to_ascii_char_list

def generate_noisy_key(index, ciphertexts):
  index_to_ascii_char_list = xor_hexes_and_find_ascii_chars(index, ciphertexts)
  plaintext = find_most_probable_plaintext(index_to_ascii_char_list, len(ciphertexts[index])/2)
  print 'plain', plaintext
  key = generate_key_from_noisy_plaintext_and_ciphertext(plaintext, ciphertexts[index])
  print 'key  ', key
  return key

def find_xored_plaintexts_list(index, ciphertexts):
  xored_plaintexts_list = []
  for i in range(10):
    if i == index:
      xored_plaintexts_list.append('') 
    else:
      xored_hexes = xor_hexes(ciphertexts[index], ciphertexts[i]).encode('hex')    
      xored_plaintexts_list.append(''.join(hex_to_ascii_char(xored_hexes)).swapcase())
    print i, xored_plaintexts_list[-1]
  return xored_plaintexts_list

def find_space_indices(xored_plaintexts_list):
  min_len = sorted([ len(i) for i in xored_plaintexts_list ])[1]
  space_indices = []
  for i in range(min_len):
    column = [ xored_plaintext[i] for xored_plaintext in xored_plaintexts_list if xored_plaintext != '']
    is_column_space = reduce(lambda x, y : x + (y == '_' or str.isalpha(y)), column, 0) >= len(column) - 1   
    if is_column_space:
      space_indices.append(i) 
  print 'space indices', space_indices
  return space_indices

def guess_cyphertext(index, ciphertexts, plaintexts):
  xored_plaintexts_list = find_xored_plaintexts_list(index, ciphertexts)
  space_indices = find_space_indices(xored_plaintexts_list)
  for i, xored_plaintexts in enumerate(xored_plaintexts_list):
    if i == index:
      plaintexts[i].extend([ (space_index, '_') for space_index in space_indices]) 
    else:
      plaintexts[i].extend([ (space_index, xored_plaintexts[space_index]) for space_index in space_indices ])
  for i in range(len(ciphertexts)):
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

  key = xor_string_hex('The ciphertext produced by a weak encryption algorithm looks as good as ciphertext produced by ', ciphertexts[3])
  for ciphertext in ciphertexts:
    print len(ciphertext), len(ciphertext)/2
    print xor_string_hex(key, ciphertext)
  solution = xor_string_hex(key, secret_ciphertext)
  print '--', solution, '--'
  print len(solution), len(secret_ciphertext)/2
#  for i, ciphertext in enumerate(ciphertexts):
#    print i, ciphertext
#  print ''
#
#  plaintexts = defaultdict(list) 
#
#  check(0, ciphertexts, plaintexts)
#  check(1, ciphertexts, plaintexts)
#  check(2, ciphertexts, plaintexts)
#  check(3, ciphertexts, plaintexts)
#  check(4, ciphertexts, plaintexts)
#  check(5, ciphertexts, plaintexts)
#  check(6, ciphertexts, plaintexts)
#  check(7, ciphertexts, plaintexts)
#  check(8, ciphertexts, plaintexts)
#  check(9, ciphertexts, plaintexts)

#  noisy_keys = []
#  for i in range(len(ciphertexts)):
#    noisy_keys.append(generate_noisy_key(i, ciphertexts))
#
#  for i, key in enumerate(noisy_keys):
#    print i, key 
#
#  key = merge_noisy_keys(noisy_keys)
#
#  print key
#
#  for ciphertext in ciphertexts:
#    print 'ciphertext', ciphertext[:50] 
#    print 'xor', ''.join(hex_to_ascii_char(xor_hexes(ciphertext[:50], key).encode('hex'))) 

if __name__ == '__main__':
  main()
