#!/usr/bin/python 

def xor_strings(xs, ys):
  return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def hexed_xor(a, b):
  return "".join(chr(ord(aa) ^ ord(bb)) for aa, bb in zip(a, b)).encode('hex')

def get_binary_key(input_string, hexed_encryption):
  encrypted_string = hexed_encryption.decode('hex')
  return xor_strings(input_string, encrypted_string)

def main():
  string = 'attack at dawn'
  encrypted = '6c73d5240a948c86981bc294814d'
  key = get_binary_key(string, encrypted)
  print xor_strings(key, string).encode('hex'), 'dawn enc'
  print encrypted, 'input enc'
  print xor_strings(key, 'attack at dusk').encode('hex')  

if __name__ == '__main__':
  main()

