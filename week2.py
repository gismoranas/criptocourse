#!/usr/bin/python2.7 

from cripto_utils import *


def main():
	for text in ['We see immediately that one needs little information to begin to break down the process.',
'An enciphering-deciphering machine (in general outline) of my invention has been sent to your organization.',
'The most direct computation would be for the enemy to try all 2^r possible keys, one by one.',
'The significance of this general conjecture, assuming its truth, is easy to see. It means that it may be feasible to design ciphers that are effectively unbreakable.']:
		print len(text)
	zeros = ['9d1a4f78cb28d863', '7b50baab07640c3d', '290b6e3a39155d6f', '5f67abaf5210722b']
	ones = ['75e5e3ea773ec3e6', 'ac343a22cea46d60', 'd6f491c5b645c008', 'bbe033c00bc9330e']
	zeros_left = [ num[:len(num)/2] for num in zeros ]
	ones_left = [ num[:len(num)/2] for num in ones ]
	zeros_right = [ num[len(num)/2:] for num in zeros ]
	ones_right = [ num[len(num)/2:] for num in ones ]

	for zero, one in zip(zeros, ones):
		print zero, one, xor_hexes(zero, one).encode('hex')

	for i in zeros, ones, zeros_left, ones_left, zeros_right, ones_right:
		print i

	for left, right in zip(zeros_left, zeros_right):
		print left, right, xor_hexes(left, right).encode('hex')
 	
if __name__ == '__main__':
  main()

