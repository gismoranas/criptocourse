#!/usr/bin/python 

from Crypto.Cipher import AES

from crypto_utils import * 

def encrypt_cbc(plaintext_as_hex, key_as_hex, initialization_vector_as_hex):
  initialization_vector = hex_to_string(initialization_vector_as_hex)
  cipher = AES.new(hex_to_string(key_as_hex), AES.MODE_ECB, initialization_vector)
  encrypted_plaintext = initialization_vector
  xor_input = initialization_vector
  for plaintext_block in [ plaintext_as_hex[i:i+16] for i in range(0, len(plaintext_as_hex), 16) ]:
    encrypted_block += cipher.encrypt(xor_strings(hex_to_string(plaintext_block), xor_input))
    encrypted_plaintext += encrypted_block
    xor_input = encrypted_block 
  return encrypted_plaintext

def decrypt_cbc(ciphertext_as_hex, key_as_hex):
  xor_input = ciphertext_as_hex[0:32] 
  initialization_vector = xor_input.decode('hex')
  cipher = AES.new(key_as_hex.decode('hex'), AES.MODE_ECB, initialization_vector)
  plaintext = ''
  for ciphertext_block in [ ciphertext_as_hex[i:i+32] for i in range(32, len(ciphertext_as_hex), 32) ]:
    plaintext += xor_string_hex(cipher.decrypt(ciphertext_block.decode('hex')), xor_input)
    xor_input = ciphertext_block
  return remove_padding(plaintext)

def remove_padding(plaintext):
  plaintext_as_hex = plaintext.encode('hex')
  last_hex = hex_to_int(plaintext_as_hex[-2:])[0]  
  if (last_hex) <= 16:
    plaintext_as_hex = plaintext_as_hex[:-last_hex*2]
  return plaintext_as_hex.decode('hex')

def decrypt_ctr(ciphertext_as_hex, key_as_hex):  
  print len(ciphertext_as_hex)
  if (len(ciphertext_as_hex) % 32 != 0):
    while (len(ciphertext_as_hex) % 32 != 0):
      ciphertext_as_hex += '00' 
  print len(ciphertext_as_hex)
  initialization_vector = ciphertext_as_hex[:32].decode('hex')
  cipher = AES.new(key_as_hex.decode('hex'), AES.MODE_ECB, initialization_vector)
  plaintext = ''
  for ciphertext_block in [ ciphertext_as_hex[i:i+32] for i in range(32, len(ciphertext_as_hex), 32) ]:
    plaintext += xor_hexes(cipher.encrypt(initialization_vector).encode('hex'), ciphertext_block)
    initialization_vector_as_hex = initialization_vector.encode('hex') 
    last_increased = hex(int(initialization_vector_as_hex[-4:], 16) + 1)[2:]
    initialization_vector = (initialization_vector_as_hex[:-4] + last_increased).decode('hex')
  return plaintext 

def main():  
  ctr_keys = ['36f18357be4dbd77f050515c73fcf9f2', '36f18357be4dbd77f050515c73fcf9f2']
  ctr_ciphertexts = ['69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329',
    '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451']
  for key, ciphertext in zip(ctr_keys, ctr_ciphertexts):
    print decrypt_ctr(ciphertext, key)
    print 'len encoded ', len(decrypt_ctr(ciphertext, key).encode('hex'))
 
  cbc_keys = [ '140b41b22a29beb4061bda66b6747e14',
          '140b41b22a29beb4061bda66b6747e14'] 
  cbc_ciphertexts = ['4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81',
    '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253']

  for key, ciphertext in zip(cbc_keys, cbc_ciphertexts):    
    plaintext = decrypt_cbc(ciphertext, key)
    print '--', plaintext, '--'

if __name__ == '__main__':
  main()
