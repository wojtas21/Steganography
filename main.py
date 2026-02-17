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

def encode(image_path, message, output_path):
    image = Image.open(image_path)
    pixels = list(image.getdata())

    message += DELIMITER
    binary_message = text_to_binary(message)

    if len(binary) > len(pixels) * 3:
        raise ValueError("The message is too long for this image!")
    
    new_pixels = []
    msg_index = 0
    
    for pixel in pixels:
        r, g, b = pixel

        if msg_index < len(binary_msg):
            r = (r & ~1) | int(binary_msg[msg_index])
            msg_index += 1
        if msg_index < len(binary_msg):
            g = (g & ~1) | int(binary_msg[msg_index])
            msg_index += 1
        if msg_index < len(binary_msg):
            b = (b & ~1) | int(binary_msg[msg_index])
            msg_index += 1


        new_pixels.append((r, g, b))

    image.putdata(new_pixels)
    image.save(output_path)
    print("The message has been encoded successfully!")
