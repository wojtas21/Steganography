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
    # Open the input image and extract pixel data as a list of RGB tuples
    image = Image.open(image_path)
    pixels = list(image.getdata())

    # Append delimiter to mark the end of the hidden message during decoding
    message += DELIMITER

    # Convert full message to a binary string
    binary_message = text_to_binary(message)

    # Check if the image has enough capacity (3 bits per pixel: R, G, B)
    if len(binary_message) > len(pixels) * 3:
        raise ValueError("The message is too long for this image!")

    new_pixels = []
    msg_index = 0 # Tracks current position in the binary message

    for pixel in pixels:
        # Support both RGB and RGBA images by taking only first 3 channels
        r, g, b = pixel[:3]

        # Replace the least significant bit (LSB) of each color channel
        # with the next bit from the secret message
        if msg_index < len(binary_message):
            r = (r & ~1) | int(binary_message[msg_index])
            msg_index += 1
        if msg_index < len(binary_message):
            g = (g & ~1) | int(binary_message[msg_index])
            msg_index += 1
        if msg_index < len(binary_message):
            b = (b & ~1) | int(binary_message[msg_index])
            msg_index += 1

        new_pixels.append((r, g, b))
        
 # Create a new image with modified pixels and save the encoded result
    with Image.open(image_path) as image:
        image.putdata(new_pixels)
        image.save(output_path)

    print("The message has been encoded successfully!")
