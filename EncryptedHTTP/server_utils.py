from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from base64 import b64encode, b64decode
import time
from hashlib import sha256
import json
import string
import random
import requests

class CA:
    """ Acts as the CA for server and client certificate generation.\n

        Not meant to be imported for use aside from inside the module.
    """
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

    def create_server_certificate(self, public_key_bytes: bytes, name: str, location: str = 'None'):
        """ Creates a certificate for the Server.\n
            
            Parameters:\n
              • public_key_bytes: `bytes` (The server's public key in `bytes`)\n
              • name: `str` (Name of the server)\n
              • location: `str` (Location of the server)\n

            Returns:\n
              • `dict[str]`\n

            Example::\n
              from EncryptedHTTP.server_utils.ca import CA
              ca = CA()
              server_certificate = ca.create_server_certificate(public_key_bytes=public_key_bytes, name, location)
        """
        public_key_encoded = b64encode(public_key_bytes).decode()
        certificate = {
            'Public Key': public_key_encoded,
            'Generation Time': str(time.time()),
            'Name': name,
            'Location': location,
            'CA': 'HTTP-Less Authentication'
        }

        template = certificate.copy() # Copy the certificate
        template = json.dumps(template).encode() # Convert the copied certificate to str

        hashed_certificate = sha256(template).hexdigest().encode() # Hash the copied certificate

        ca_signature = self.private_key.sign(
            data=hashed_certificate,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        ) # Sign the hashed certificate copy

        ca_signature_encoded = b64encode(ca_signature)
        ca_signature = ca_signature_encoded.decode()

        certificate.update({'CA Signature': ca_signature})

        return certificate

    def create_client_certificate(self, client_public_key_bytes: bytes, client_name: str, client_location: str = "None"):
        """ Creates a certificate for the Client.\n
            
            Parameters:\n
              • public_key_bytes: `bytes` (The client's public key in `bytes`)\n
              • name: `str` (Name of the client)\n
              • location: `str` (Location of the client)\n

            Returns:\n
              • `dict[str]`\n

            Example::\n
              from EncryptedHTTP.server_utils.ca import CA
              ca = CA()
              client_certificate = ca.create_client(public_key_bytes=public_key_bytes, name, location)
        """
        public_key_encoded = b64encode(client_public_key_bytes).decode()
        expiry = str(time.time() + 864000)
        certificate = {
            'Public Key': public_key_encoded,
            'Generation Time': str(time.time()),
            'Name': client_name,
            'Location': client_location,
            'CA': 'HTTP-Less Authentication',
            'Expiry': expiry
        }

        template = certificate.copy() # Copy the certificate
        template = json.dumps(template).encode() # Convert the copied certificate to str

        hashed_certificate = sha256(template).hexdigest().encode() # Hash the copied certificate

        ca_signature = self.private_key.sign(
            data=hashed_certificate,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        ) # Sign the hashed certificate copy

        ca_signature_encoded = b64encode(ca_signature)

        ca_signature = ca_signature_encoded.decode()
        certificate.update({'CA Signature': ca_signature})

        return certificate
    
class Server:
    """ Initializes the server. """
    def __init__(self, name: str, location: str = "None") -> None:
        self.DEFAULT_HEADERS = list(requests.utils.default_headers().keys()) + ["Host"]
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )
        self.certificate: dict = None
        self.ca = CA()
        self.name = name
        self.location = location

    def create_certificate(self, server_public_key_bytes: bytes):
        """ Creates a certificate for the server from the CA.\n
         
            Parameters:\n
              • server_public_key_bytes: `bytes` (The server's public key in `bytes`)\n

            Returns:\n
              • `None`

            Example::\n
              from EncryptedHTTP.server_utils.server import Server
              server = Server()
              server.create_certificate(server_public_key_bytes=server_public_key_bytes)            
        """
        self.certificate = self.ca.create_server_certificate(server_public_key_bytes, self.name, self.location)

class ExtraUtils:
    """ Base class for extra server utilities """
    def validate_client_certificate(certificate: dict, server: Server):
        """ Validates the client certificate\n

            Parameters:\n
              • certificate: `dict[str, str]` (The decrypted client certificate in the form of a `dict`)\n
              • server: `Server` (The initialized `Server` object)\n

            Returns:\n
              • `bool`\n
        """
        expiry_str: str = certificate.get("Expiry")
        expiry: float = float(expiry_str)

        if time.time() > expiry:
            return False
        
        ca_signature = certificate.get("CA Signature")

        certificate.pop("CA Signature")
        certificate_str = json.dumps(certificate).encode()

        hashed_certificate = sha256(certificate_str).hexdigest().encode()

        ca_signature_decoded = b64decode(ca_signature)

        try:
            server.ca.public_key.verify(
                signature=ca_signature_decoded,
                data=hashed_certificate,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )

        except Exception:
            return False
        else:
            return True
        
    def generate_session_token(length: int = 10):
        """ Generates a session token of desired length.\n

            Parameters:\n
              • length: `int` (The desired length of the session token)\n

            Returns:\n
              • `str`
        """
        s = list(string.ascii_letters + string.digits)

        token_list = random.sample(s, length)

        token = ""

        for i in token_list:
            token += i

        return token

    def load_raw_data(tokenfile: str):
        """ Default function to load raw data from the token file.\n
            Can be replaced with a custom function to load raw data while intializing `Server` object.\n

            Parameters:\n
              • tokenfile: `str` (The file path where the user tokens are stored.)\n

            Returns:\n
              • `dict`
        """
        with open(tokenfile, "r") as f:
            data: dict = json.load(f)
        return data

    def save_token(raw_data: dict, tokenfile: str):
        """ Default function to save tokens to the token file.\n
            Can be replaced with a custom function to save tokens while intializing `Server` object.\n

            Parameters:\n
              • raw_data: `dict` (The raw data to be stored)
              • tokenfile: `str` (The file path where the user tokens are stored)\n

            Returns:\n
              • `None`
        """
        with open(tokenfile, "w") as f:
            json.dump(raw_data, f, indent=4)

    def validate_loaded_raw_data(raw_data: dict):
        """ Validates the raw data loaded.\b

            Parameters:\n
              • raw_data: `dict` (The raw data.)\n

            Returns:\n
              • `bool`\n
        """
        try:
            for key in raw_data:
                ind: dict = raw_data.get(key)
                ind_keys = ind.keys()
                if "Key" in ind_keys and "Expiry" in ind_keys:
                    continue
                else:
                    raise Exception
        except Exception:
            return False
        else:
            return True

    def form_raw_data(token: str, symmetric_key: bytes, expiry: str, load_tokens_func, tokenfile):
        """ Forms encrypted raw data from the loaded raw data.\n

            Parameters:\n
              • token: `str` (The user token)\n
              • symmetric_key: `bytes` (The symmetric key of the user token)\n
              • expiry: `str` (The expiry date of the user token)\n
              • load_tokens_func: `function` (The function assigned to load the tokens)\n
              • tokenfile: `str` (The file path where the user tokens are stored)\n

            Returns:\n
              • `dict`\n
        """
        if load_tokens_func == ExtraUtils.load_raw_data:
            d: dict = ExtraUtils.load_raw_data(tokenfile)
        else:
            d: dict = ExtraUtils.load_raw_data()
        if not ExtraUtils.validate_loaded_raw_data(d):
            err = "Invalid Loaded Raw Data"
            raise Exception(err)
        symmetric_key_encoded = b64encode(symmetric_key).decode()
        d.update({token: {"Key": symmetric_key_encoded, "Expiry": expiry}})
        return d
