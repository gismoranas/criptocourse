def ascii_int_to_char(number):
  return str(unichr(number))

def find_space_indices_and_chars(hex_1, hex_2):
  hex_xor = xor_hexes(hex_1, hex_2).encode('hex') 
  ascii_code_xor = [int(hex_xor[j:j+2], 16) for j in range(0, len(hex_xor), 2)]  
  return {ind : ascii_int_to_char(num) for ind, num in enumerate(ascii_code_xor) if is_ascii_int(num)}

def is_ascii_int(number):
  return (number >= 65 and number <= 90) or (number >= 97 and number <=122)

def xor_hexes(hex_1, hex_2):
  return xor_strings(hex_1.decode('hex'), hex_2.decode('hex'))

def xor_string_hex(string, hex_num):
  return xor_strings(string, hex_num.decode('hex')) 

def xor_strings(string_1, string_2):     
    if len(string_1) > len(string_2):
        return ''.join([chr(ord(x) ^ ord(y)) for (x, y) in zip(string_1[:len(string_2)], string_2)])
    else:
        return ''.join([chr(ord(x) ^ ord(y)) for (x, y) in zip(string_1, string_2[:len(string_1)])])

