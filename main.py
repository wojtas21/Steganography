from PIL import Image
import tkinter as tk
from tkinter import filedialog, messagebox

# Cryptography related imports
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DELIMITER = "###END###"  # Delimiter to mark the end of the hidden message


# ---------- binary helpers ----------

def text_to_binary(text):
    # Converts text to a binary string
    return ''.join(format(ord(c), '08b') for c in text)


def binary_to_text(binary):
    # Converts a binary string back to text
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(c, 2)) for c in chars)


# ---------- crypto ----------

def derive_key(password: str, salt: bytes) -> bytes:
    # Derives a cryptographic key from a password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())


def encrypt_message(message: str, password: str) -> bytes:
    # Encrypts a message using AESGCM with a derived key
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password, salt)

    aes = AESGCM(key)
    nonce = os.urandom(12)  # Generate a random nonce

    ciphertext = aes.encrypt(nonce, message.encode(), None)

    return salt + nonce + ciphertext  # Return salt, nonce, and ciphertext


def decrypt_message(data: bytes, password: str) -> str:
    # Decrypts a message encrypted with AESGCM
    salt = data[:16]  # Extract salt
    nonce = data[16:28]  # Extract nonce
    ciphertext = data[28:]  # Extract ciphertext

    key = derive_key(password, salt)
    aes = AESGCM(key)

    plaintext = aes.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


# ---------- steganography ----------

def encode(image_path, message, password, output_path):
    # Encodes a message into an image using LSB steganography
    image = Image.open(image_path)
    pixels = list(image.getdata())

    # Choose mode: encrypted or raw
    if password:
        payload = b"ENC" + encrypt_message(message, password)  # Encrypt if password provided
    else:
        payload = b"RAW" + message.encode()  # Otherwise, store as raw bytes

    data = payload + DELIMITER.encode()
    binary_message = ''.join(format(byte, '08b') for byte in data)

    # Check if message is too long for the image
    if len(binary_message) > len(pixels) * 3:
        raise ValueError("Message too long for this image.")

    new_pixels = []
    msg_index = 0

    # Iterate through pixels and modify LSB of RGB channels
    for pixel in pixels:
        r, g, b = pixel[:3]

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

    image.putdata(new_pixels)

    # Ensure output path is PNG
    if not output_path.lower().endswith(".png"):
        output_path += ".png"

    image.save(output_path)


def decode(image_path, password):
    # Decodes a hidden message from an image
    image = Image.open(image_path)
    pixels = list(image.getdata())

    binary_msg = ""
    # Extract LSB from RGB channels to reconstruct binary message
    for pixel in pixels:
        for color in pixel[:3]:
            binary_msg += str(color & 1)

    # ---------- TRY NEW BYTE FORMAT ----------
    # Convert binary string to bytes
    data_bytes = bytes(
        int(binary_msg[i:i+8], 2)
        for i in range(0, len(binary_msg), 8)
    )

    # Check for delimiter and process payload
    if DELIMITER.encode() in data_bytes:
        payload = data_bytes.split(DELIMITER.encode())[0]

        if payload.startswith(b"RAW"):
            return payload[3:].decode()  # Decode raw message

        if payload.startswith(b"ENC"):
            if not password:
                raise ValueError("Password required for this file.")
            return decrypt_message(payload[3:], password)  # Decrypt message

    # ---------- FALLBACK: OLD STRING FORMAT ----------
    # Fallback for messages encoded with an older string format
    try:
        text = binary_to_text(binary_msg)

        if DELIMITER in text:
            return text.split(DELIMITER)[0]

    except Exception:
        pass

    return None # No hidden message found


# ---------------- GUI ----------------

def choose_image():
    # Opens a file dialog to select an image file
    return filedialog.askopenfilename(filetypes=[("PNG files", "*.png")])


def encode_action():
    # Handles the encode button action
    img = choose_image()
    if not img:
        return

    msg = message_entry.get("1.0", tk.END).strip()
    if not msg:
        messagebox.showerror("Error", "Message is empty.")
        return

    password = password_entry.get().strip()

    out = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG files", "*.png")]
    )
    if not out:
        return

    try:
        encode(img, msg, password, out)
        messagebox.showinfo("Success", "Message encoded.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def decode_action():
    # Handles the decode button action
    img = choose_image()
    if not img:
        return

    password = password_entry.get().strip()

    try:
        text = decode(img, password)
        if text:
            messagebox.showinfo("Hidden message:", text)
        else:
            messagebox.showwarning("Result", "No hidden message found.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Main GUI window setup
root = tk.Tk()
root.title("PNG Steganography Tool")
root.geometry("400x340")

# Message input field
tk.Label(root, text="Message").pack(pady=5)
message_entry = tk.Text(root, height=6)
message_entry.pack(fill="both", padx=10)

# Password input field
tk.Label(root, text="Password (optional)").pack(pady=5)
password_entry = tk.Entry(root, show="*")
password_entry.pack(fill="x", padx=10)

# Encode and Decode buttons
tk.Button(root, text="Encode into PNG", command=encode_action).pack(pady=5)
tk.Button(root, text="Decode from PNG", command=decode_action).pack(pady=5)

root.mainloop()  # Start the GUI event loop