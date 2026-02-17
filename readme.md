# PNG Steganography Tool

This Python application provides a user-friendly graphical interface for hiding secret messages within PNG image files using Least Significant Bit (LSB) steganography. It also offers the option to encrypt your messages for an added layer of security, making it harder for unauthorized individuals to read them even if they discover the hidden data.

## Features

*   **LSB Steganography:** Embeds text messages into the least significant bits of the R, G, and B channels of each pixel in a PNG image, making the changes imperceptible to the human eye.
*   **Message Encryption:** Securely encrypts hidden messages using AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) with a password-derived key, utilizing the `cryptography` library.
*   **Intuitive GUI:** A simple and easy-to-use Tkinter-based interface for encoding and decoding operations.
*   **Password Protection:** Messages can be hidden with or without a password. A password is required to decrypt and retrieve encrypted messages.
*   **Error Handling:** Includes checks to prevent messages too long for the chosen image and handles incorrect password attempts for encrypted messages.

## Dependencies

This project requires the following Python libraries:

*   **Pillow (PIL):** For image manipulation (opening, processing, and saving PNG files).
*   **cryptography:** For secure message encryption and decryption.
*   **tkinter:** (Usually comes pre-installed with Python) For the graphical user interface.

## Installation

Follow these steps to set up the project on your local machine:

1.  **Clone the repository (if applicable):**
    ```bash
    git clone https://github.com/wojtas21/Steganography.git
    cd steganography
    ```

2.  **Create a virtual environment:**
    It's recommended to use a virtual environment to manage project dependencies.
    ```bash
    python3 -m venv .venv
    ```

3.  **Activate the virtual environment:**
    *   **On macOS/Linux:**
        ```bash
        source .venv/bin/activate
        ```
    *   **On Windows (Command Prompt):**
        ```bash
        .venv\Scripts\activate.bat
        ```
    *   **On Windows (PowerShell):**
        ```bash
        .venv\Scripts\Activate.ps1
        ```

4.  **Install the required libraries:**
    ```bash
    pip install Pillow cryptography
    ```

## How to Use

Once installed, you can run the application and use its GUI.

1.  **Run the application:**
    ```bash
    python main.py
    ```
    This will open the "PNG Steganography Tool" window.

2.  **Encoding a Message:**
    *   **Message Field:** Type or paste the secret message you wish to hide into the "Message" text area.
    *   **Password (Optional):** If you want to encrypt your message, enter a strong password in the "Password (optional)" field. *Remember this password, as it will be needed for decoding!* If you leave this blank, the message will be hidden without encryption.
    *   **Choose Image:** Click the "Encode into PNG" button. A file dialog will appear.
    *   **Select Input Image:** Choose the `.png` image file into which you want to embed the message.
    *   **Save Output Image:** Another file dialog will ask you where to save the new image with the hidden message. Provide a name (e.g., `output_image.png`). The tool will automatically ensure it's saved as a PNG.
    *   A success message will confirm the encoding, or an error message will appear if the message is too long or another issue occurs.

3.  **Decoding a Message:**
    *   **Password (if encrypted):** If the hidden message was encrypted, enter the exact password used during encoding into the "Password (optional)" field. If the message was not encrypted, you can leave this field blank.
    *   **Choose Image:** Click the "Decode from PNG" button. A file dialog will appear.
    *   **Select Image:** Choose the `.png` image file that contains the hidden message.
    *   **View Message:** If a message is found, a pop-up window will display the hidden text. If the message was encrypted and the wrong password (or no password) was provided, an error will be shown. If no message is found, a warning will be displayed.

## Technical Details

*   **LSB Steganography:** The `encode` function iterates through each pixel's RGB color channels. For every bit in the binary representation of the secret message, it modifies the least significant bit (LSB) of a color channel (R, then G, then B). This change is minimal (a pixel value changes by at most 1), making it visually imperceptible.
*   **Message Delimiter:** A `###END###` delimiter is embedded after the message to precisely locate where the hidden message ends during decoding, preventing the extraction of random image data.
*   **Encryption (AES-GCM):**
    *   **Key Derivation:** `PBKDF2HMAC` is used to derive a strong encryption key from the user's password and a randomly generated `salt`. This protects against brute-force attacks on the password.
    *   **AES-GCM:** The derived key is then used with `AESGCM` to encrypt the message. `AESGCM` is an authenticated encryption mode, meaning it not only encrypts the data but also provides integrity and authenticity checks to ensure the message hasn't been tampered with.
    *   **Nonce:** A unique, randomly generated `nonce` (number used once) is used with each encryption to prevent chosen-plaintext attacks.
    *   The `salt`, `nonce`, and `ciphertext` are concatenated and then embedded into the image, along with a `b"ENC"` prefix to indicate encryption.

## Security Considerations

*   **Password Strength:** For encrypted messages, the security relies heavily on the strength of your chosen password. Use long, complex, and unique passwords.
*   **Image Choice:** While LSB steganography is subtle, repeatedly embedding messages into the same image or using images with very limited color palettes might introduce statistical anomalies. Using high-quality, diverse images is generally recommended.
*   **Detection:** Advanced steganographic analysis tools (steganalysis) might be able to detect the presence of hidden data, especially if the technique is well-known. Encryption helps protect the *content* of the message even if its presence is detected.
*   **File Format:** This tool specifically works with PNG files, which are lossless. Lossy compression formats like JPG can destroy the hidden data during saving.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details (if you plan to add one, otherwise omit this section or specify another license).
