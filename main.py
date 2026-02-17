from PIL import Image

DELIMITER = "###END###"

def text_to_binary(text):
    # Convert each character to its ASCII integer (ord),
    # then format it as an 8 bit binary string and join all bits together
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary):
    # Split the binary string into 8-bit chunks (one byte per character),
    # convert each byte from binary to integer, then to its ASCII character,
    # and join everything back into the original text
    chars = [binary[i:i+8] for i in range(0,len(binary), 8)]
    return ''.join(chr(int(c, 2)) for c in chars)