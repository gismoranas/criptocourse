def random(size=16):
    return open("/dev/urandom").read(size)

def encrypt(key, cyphertext):
    c = xor_strings(key, cyphertext)
    print c.encode('hex')
    return c

def find_space_indices_for_strings(string1, string2):
  hex_xor = xor_hexes(string1, string2).encode('hex') 
  ascii_code_xor = [int(hex_xor[j:j+2], 16) for j in range(0, len(hex_xor), 2)]  
  return [ind for ind, num in enumerate(ascii_code_xor) if (num >= 65 and num <= 90) or (num >= 97 and num <=122)]

def find_same_letter_indices_for_strings(string1, string2):
  hex_xor = xor_hexes(string1, string2).encode('hex') 
  ascii_code_xor = [int(hex_xor[j:j+2], 16) for j in range(0, len(hex_xor), 2)]  
  return [ind for ind, num in enumerate(ascii_code_xor) if (num == 0)]

def find_space_indices(index):
  space_indices = []
  for i in range(0, 10):
    space_indices.extend(find_space_indices_for_strings(cyphertext[index], cyphertext[i]))
  return list(set(space_indices))  

def decrypt_strict():
  space_indices = []
  for i in range(0, 10):
    space_indices.append(find_space_indices(i))  
  plaintext = ['*']*(len(cyphertext[10])/2)
  for i in range(0, 10):
    hexed_string = xor_hexes(cyphertext[10], cyphertext[i])
    for index in space_indices[i]:
      if index < len(plaintext): 
        plaintext[index] = hexed_string[index]   
  print sorted(list(itertools.chain.from_iterable(space_indices)))
  print plaintext

def print_xor_ascii():
  for i in range(0, 128):
    hex_string = hex(i)[2:].zfill(2)
    string = hex_string.decode('hex')
    print hex_string, string, xor_hexes(hex_string, '20')

def find_space_indices_strict(index):
  space_xors = []
  common_indices = []
  for i in range(0, 10):
    hex_xor = xor_hexes(cyphertext[index], cyphertext[i]).encode('hex') 
    ascii_code_xor = [int(hex_xor[j:j+2], 16) for j in range(0, len(hex_xor), 2)]  
    space_xors.append({ind : (num, chr(num)) for ind, num in enumerate(ascii_code_xor) if (num >= 65 and num <= 90) or (num >= 97 and num <=122)})
    if len(common_indices) == 0:
      common_indices = space_xors[-1].keys()
    else:
      if len(space_xors[-1]) != 0:
        common_indices = list(set(common_indices) & set(space_xors[-1].keys()))
      #else:
        #print 'empty space xor'
    #print sorted(space_xors[-1].items())

  return common_indices 


