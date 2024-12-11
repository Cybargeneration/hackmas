import os
import subprocess

# Ensure the static directory exists
if not os.path.exists("static"):
    os.makedirs("static")

def embed_message(image_path, output_image, passphrase, message_file):
    """
    Embed a secret message into an image using steghide.

    :param image_path: Path to the original image file.
    :param output_image: Path to the output image file with the embedded message.
    :param passphrase: Passphrase to secure the hidden message.
    :param message_file: Path to the text file containing the message to hide.
    """
    try:
        # Embed the message into the image
        subprocess.run(
            ["steghide", "embed", "-ef", message_file, "-cf", image_path, "-sf", output_image, "-p", passphrase],
            check=True
        )
        print(f"Message successfully embedded in {output_image}.")
    except subprocess.CalledProcessError as e:
        print(f"Error embedding message: {e}")


def extract_message(image_path, passphrase, output_message_file):
    """
    Extract the hidden message from an image using steghide.

    :param image_path: Path to the image file containing the hidden message.
    :param passphrase: Passphrase used to embed the hidden message.
    :param output_message_file: Path to save the extracted message.
    """
    try:
        # Extract the message from the image
        subprocess.run(
            ["steghide", "extract", "-sf", image_path, "-xf", output_message_file, "-p", passphrase],
            check=True
        )
        print(f"Message successfully extracted to {output_message_file}.")
    except subprocess.CalledProcessError as e:
        print(f"Error extracting message: {e}")


if __name__ == "__main__":
    # Example usage
    original_image = "static/sql_image.jpg"         # Path to the original image
    stego_image = "static/stego_image.jpg"          # Output image with hidden message
    secret_message_file = "message.txt"            # Text file containing the hidden message
    extracted_message_file = "extracted_message.txt"  # File to save the extracted message
    passphrase = "Hackmas"                         # Passphrase to secure the hidden message

    # Write a secret message to a file
    with open(secret_message_file, "w") as f:
        f.write("CTF{play-with-me}")  # Replace this with your hidden message

    # Embed the message into the image
    embed_message(original_image, stego_image, passphrase, secret_message_file)

    # Extract the message back
    extract_message(stego_image, passphrase, extracted_message_file)

