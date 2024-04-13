import tkinter as tk
from tkinter import ttk
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

class CertificateApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Certificate Generator")
        self.root.geometry("450x400")
        self.root.attributes("-alpha", 0.95)  # Set window transparency
        self.root.configure(bg="#003366")  # Setting background color to Bilain blue

        self.create_inputs()
        self.generate_public_key_button = ttk.Button(root, text="Generate Public Key", command=self.generate_public_key, style="Bilain.TButton")
        self.generate_public_key_button.pack(pady=10)

        self.generate_private_key_button = ttk.Button(root, text="Generate Private Key", command=self.generate_private_key, style="Bilain.TButton")
        self.generate_private_key_button.pack(pady=10)

        self.generate_certificate_button = ttk.Button(root, text="Generate Certificate", command=self.generate_certificate, style="Bilain.TButton")
        self.generate_certificate_button.pack(pady=10)

    def create_inputs(self):
        self.inputs = {}

        labels = [
            "Country (C):",
            "State (ST):",
            "Locality (L):",
            "Organization (O):",
            "Organizational Unit (OU):",
            "Common Name (CN):",
            "Email Address (EMAIL):",
            "Certificate Expiry Date :"
        ]

        for label_text in labels:
            label_frame = ttk.Frame(self.root, style="Bilain.TFrame")
            label_frame.pack(fill="x", padx=10, pady=(5, 0), side="top")

            label = ttk.Label(label_frame, text=label_text, background="#003366", foreground="#ffffff", style="WhiteText.TLabel") # Setting label color
            label.pack(side="left", padx=(0, 10))

            input_var = tk.StringVar()
            input_entry = ttk.Entry(label_frame, textvariable=input_var, width=30)
            input_entry.pack(side="right")

            # Use the first part of label text (before colon) as key
            key = label_text.split(":")[0].strip()
            self.inputs[key] = input_var

    def generate_public_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with open("public_key.key", "wb") as pub_file:
            pub_file.write(public_key_bytes)

        print("Public key generated successfully.")

    def generate_private_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open("private_key.key", "wb") as key_file:
            key_file.write(private_key_bytes)

        print("Private key generated successfully.")

    def generate_certificate(self):
        expiry_date_str = self.inputs["Certificate Expiry Date"].get()
        expiry_date = datetime.datetime.strptime(expiry_date_str, "%Y-%m-%d")

        subject_attributes = [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, self.inputs["Country (C)"].get()),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, self.inputs["State (ST)"].get()),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, self.inputs["Locality (L)"].get()),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, self.inputs["Organization (O)"].get()),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, self.inputs["Organizational Unit (OU)"].get()),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.inputs["Common Name (CN)"].get()),
            x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, self.inputs["Email Address (EMAIL)"].get())
        ]

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        subject = x509.Name(subject_attributes)
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
            private_key, hashes.SHA256(), default_backend()
        )

        issuer = subject
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now())
            .not_valid_after(expiry_date)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        )

        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
        )

        cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        pem_data = b''.join([private_key_bytes, cert_bytes])

        with open("certificate.crt", "wb") as cert_file:
            cert_file.write(cert_bytes)

        print("Certificate created successfully.")
        with open("private_key.key", "wb") as key_file:
            key_file.write(private_key_bytes)

        with open("public_key.key", "wb") as pub_file:
            pub_file.write(public_key_bytes)

        with open("certificate_&_private_key.pem", "wb") as pem_file:  # Writing .pem file
            pem_file.write(pem_data)

        print("Certificate with private key PEM file created successfully.")

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use('clam')  # Use the 'clam' theme
    style.configure("Bilain.TButton", foreground="#ffffff", background="#003366", font=('Arial', 10, 'bold'))  # Button style
    style.configure("Bilain.TFrame", background="#003366")  # Frame style
    style.configure("WhiteText.TLabel", foreground="#ffffff", background="#003366")  # Label style
    app = CertificateApp(root)
    root.mainloop()
