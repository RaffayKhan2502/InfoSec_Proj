
import gradio as gr
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
import base64
import os

# Key generation function
def generate_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_bytes.decode("utf-8"), public_bytes.decode("utf-8")

# Encryption function
def encrypt_message(public_key_pem, message):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        ephemeral_private_key = x25519.X25519PrivateKey.generate()
        shared_key = ephemeral_private_key.exchange(public_key)

        encrypted_message = base64.b64encode(
            message.encode() + shared_key
        ).decode("utf-8")

        return ephemeral_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8"), encrypted_message
    except Exception as e:
        return None, f"Encryption failed: {e}"

# Decryption function
def decrypt_message(private_key_pem, ephemeral_public_key_pem, encrypted_message):
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None
        )
        ephemeral_public_key = serialization.load_pem_public_key(
            ephemeral_public_key_pem.encode()
        )
        shared_key = private_key.exchange(ephemeral_public_key)

        decrypted_message = base64.b64decode(encrypted_message.encode())
        decrypted_message = decrypted_message[: len(decrypted_message) - len(shared_key)]

        return decrypted_message.decode("utf-8")
    except Exception as e:
        return f"Decryption failed: {e}"

# Gradio interface
def interface():
    with gr.Blocks() as demo:
        with gr.Row():
            gr.Markdown("# Post-Quantum Cryptography Web App")

        with gr.Tab("Key Generation"):
            with gr.Row():
                gen_btn = gr.Button("Generate Keys")
                private_key_out = gr.Textbox(label="Private Key", lines=5)
                public_key_out = gr.Textbox(label="Public Key", lines=5)

            gen_btn.click(generate_keys, outputs=[private_key_out, public_key_out])

        with gr.Tab("Encrypt Message"):
            with gr.Row():
                public_key_in = gr.Textbox(label="Recipient's Public Key", lines=5)
                message_in = gr.Textbox(label="Message to Encrypt")
                encrypt_btn = gr.Button("Encrypt")
            with gr.Row():
                ephemeral_pub_key_out = gr.Textbox(
                    label="Ephemeral Public Key", lines=5
                )
                encrypted_message_out = gr.Textbox(label="Encrypted Message")

            encrypt_btn.click(
                encrypt_message,
                inputs=[public_key_in, message_in],
                outputs=[ephemeral_pub_key_out, encrypted_message_out],
            )

        with gr.Tab("Decrypt Message"):
            with gr.Row():
                private_key_in = gr.Textbox(label="Your Private Key", lines=5)
                ephemeral_public_key_in = gr.Textbox(
                    label="Sender's Ephemeral Public Key", lines=5
                )
                encrypted_message_in = gr.Textbox(label="Encrypted Message")
                decrypt_btn = gr.Button("Decrypt")
            with gr.Row():
                decrypted_message_out = gr.Textbox(label="Decrypted Message")

            decrypt_btn.click(
                decrypt_message,
                inputs=[
                    private_key_in,
                    ephemeral_public_key_in,
                    encrypted_message_in,
                ],
                outputs=decrypted_message_out,
            )

    return demo

app = interface()
if __name__ == "__main__":
    app.launch()
