def int_to_ascii_char(number):
  if is_ascii_int_letter(number):
    return str(unichr(number))
  elif number == 0:
    return '_'
  else:
    return '*'

def find_ascii_chars_in_hex(hex_num):
  ascii_ints = hex_to_int(hex_num)
  return {ind : int_to_ascii_char(num) for ind, num in enumerate(ascii_ints) if is_ascii_int_letter(num)}

def hex_to_ascii_char(hex_string):
  return [ int_to_ascii_char(int_num) for int_num in hex_to_int(hex_string) ]
  
def hex_to_int(hex_string):
  return [ int(hex_string[j:j+2], 16) for j in range(0, len(hex_string), 2) ]  

def hex_to_string(hex_string):
  return ''.join(hex_to_ascii_char(hex_string))

def is_ascii_hex_letter(hex_number):
  return is_ascii_int_letter(int(hex_number, 16))

def is_ascii_int_letter(number):
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

