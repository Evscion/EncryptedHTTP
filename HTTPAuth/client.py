import requests
import json
from cryptography.fernet import Fernet as fer
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from base64 import b64encode, b64decode
from hashlib import sha256

try:
    from typing import Literal
except Exception:
    from typing_extension import Literal

class Auth:
    """ Base Class for Client-Side Authentication.\n
    
        This module is to be used for authentication requests to a server which uses/supports `HTTPAuth.server` 

        Parameters:\n
              • url: `str` (The URL of the server)
              • session_file: `str` (The file path where the client session will be stored. Must be a '.JSON' file.)
    """
    def __init__(self, url: str, session_file: str) -> None:
        """ Base Class for Client-Side Authentication.\n

            Is to be used for authentication requests to a server which uses/supports `HTTPAuth.server`\n

            Parameters:\n
              • url: `str` (The URL of the server)
              • session_file: `str` (The file path where the client session will be stored. Must be a '.JSON' file.)
        """
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.__url = url
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )
        self.certificate: dict[str, str] = None
        self.server_public_key: rsa.RSAPublicKey = None
        self.encryption_key: bytes = None
        self.token: str = None
        self.sessionfile = session_file

    def __get_server_certificate(self) -> dict[str, str]:
        """ Internal Method to get the Server Certificate. """
        response = requests.get(f"{self.__url}/certificate/get")
        response_dict: dict = json.loads(response.text)

        certificate_encoded: str = response_dict.get("Certificate")
        certificate_bytes = b64decode(certificate_encoded)

        certificate_dict: dict[str, str] = json.loads(certificate_bytes)

        server_public_key_str = certificate_dict['Public Key']
        server_public_key_bytes = b64decode(server_public_key_str)

        server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

        self.server_public_key = server_public_key

        return certificate_dict

    def __verify_server_certificate(self, server_certificate: dict[str, str]) -> bool:
        """ Internal Method to Verify Server Certificate """
        response = requests.get(f"{self.__url}/ca/get-key")
        response_dict: dict = json.loads(response.text)

        public_key_encoded = response_dict.get("Public Key")
        public_key_bytes = b64decode(public_key_encoded)

        public_key = serialization.load_pem_public_key(public_key_bytes)

        ca_signature = server_certificate.get("CA Signature")

        server_certificate.pop("CA Signature")
        server_certificate_str = json.dumps(server_certificate).encode()

        hashed_server_certificate = sha256(server_certificate_str).hexdigest().encode()

        ca_signature_decoded = b64decode(ca_signature)

        try:
            public_key.verify(
                signature=ca_signature_decoded,
                data=hashed_server_certificate,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )
        except Exception as e:
            return False
        else:
            return True

    def __create_certificate(self, name: str, location: str = None) -> None:
        """ Internal Method to Create Client Certificate """
        public_key_bytes = self.public_key_bytes
        public_key_encoded = b64encode(public_key_bytes).decode()
        name_encoded = b64encode(name.encode()).decode()

        if not location:
            location_encoded = "None"
        else:
            location_encoded = b64encode(location.encode()).decode()

        response = requests.get(f"{self.__url}/certificate/create", headers={"public_key": public_key_encoded, "name": name_encoded, "location": location_encoded})
        
        if response.status_code != 200:
            try:
                response_dict: dict = json.loads(response.text)
            except Exception:
                err = "Unexpected Error: Server returned completely invalid data."
                raise Exception(err)
            
            error = response_dict.get("Error")

            if not error:
                err = "Unexpected Error: Server returned invalid JSON data."
                raise Exception(err)
            
            err = f"Unexpected Error: Server returned - '{error}'"
            raise Exception(err)

        response_dict: dict = json.loads(response.text)

        certificate_encoded: str = response_dict.get("Certificate")
        certificate_bytes = b64decode(certificate_encoded)

        certificate_dict: dict[str, str] = json.loads(certificate_bytes)

        self.certificate = certificate_dict

    def auth(self, name: str, location: str = "None"):
        """ Authenticates the Client with the Server and establishes a secure connection.\n

            Parameters:\n
              • name: `str` (Name of the Client)\n
              • location: `str` = 'None' (Location of the Client)\n

            Example::\n
              from HTTPAuth.client import Auth as ClientAuth
              client = ClientAuth(url, session_file)
              client.auth(name, location)
         """
        server_certificate = self.__get_server_certificate()

        if not self.__verify_server_certificate(server_certificate):
            err = "Unexpected Error: Server returned invalid certificate."
            raise Exception(err)
        
        self.__create_certificate(name, location)
        
        symmetric_key = fer.generate_key()
        symmetric_key_encrypted = self.server_public_key.encrypt(
            plaintext=symmetric_key,
            padding=padding.PKCS1v15()
        )
        symmetric_key_encoded = b64encode(symmetric_key_encrypted).decode()
        certificate_dict = self.certificate
        certificate_bytes = json.dumps(certificate_dict).encode()
        certificate_encoded = b64encode(certificate_bytes).decode()
        response = requests.post(f"{self.__url}/auth", headers={'Certificate': certificate_encoded, 'Key': symmetric_key_encoded})
        if response.status_code != 200:
            try:
                response_dict: dict = json.loads(response.text)
            except Exception:
                err = "Unexpected Error: Server returned completely invalid data."
                raise Exception(err)
            
            error = response_dict.get("Error")

            if not error:
                err = "Unexpected Error: Server returned invalid JSON data."
                raise Exception(err)
            
            err = f"Unexpected Error: Server returned - '{error}'"
            raise Exception(err)
        
        response_dict: dict = json.loads(response.text)

        token_encoded = response_dict.get("Token")

        token = b64decode(token_encoded).decode()

        self.encryption_key = symmetric_key

        self.__auth = True

        self.token = token

    def save_session(self, passphrase: bytes = b"passphrase"):
        """ Saves the current Client status/session in the session file.

            Parameters:\n
              • passphrase: `bytes` = b"passphrase" (Passphrase to decode the private key before converting it to `bytes`)\n
        
            Example::\n
              from HTTPAuth.client import Auth as ClientAuth
              client = ClientAuth(url, session_file)
              # Optional: Authorize the client using `client.auth()`
              client.save_session(passphrase)
        """
        private_key_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        )
        private_key_encoded = b64encode(private_key_bytes).decode()

        public_key_encoded = b64encode(self.public_key_bytes).decode()

        server_public_key_bytes = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

        server_public_key_encoded = b64encode(server_public_key_bytes).decode()

        key_encoded = b64encode(self.encryption_key).decode()

        passphrase_encoded = b64encode(passphrase).decode()

        data = {
            "Public Key": public_key_encoded,
            "Private Key": private_key_encoded,
            "Server Public Key": server_public_key_encoded,
            "Certificate": self.certificate,
            "Encryption Key": key_encoded,
            "Token": self.token,
            "Passphrase": passphrase_encoded,
            "Auth": self.__auth
        }

        with open(self.sessionfile, "w") as f:
            json.dump(data, f, indent=4)

    def load_session(self):
        """ Loads the saved session from the session file.

            Example::\n
              from HTTPAuth.client import Auth as ClientAuth
              client = ClientAuth(url, session_file)
              client.load_session()
        """
        with open(self.sessionfile, "r") as f:
            data: dict = json.load(f)

        if data == {}:
            err = "No Session Stored"
            raise Exception(err)
        
        self.__auth = data.get("Auth")
        
        public_key_encoded = data.get("Public Key")

        self.public_key_bytes = b64decode(public_key_encoded)
        self.public_key = serialization.load_pem_public_key(self.public_key_bytes)

        private_key_encoded = data.get("Private Key")
        passphrase_encoded = data.get("Passphrase")
        
        private_key_bytes = b64decode(private_key_encoded)
        passphrase = b64decode(passphrase_encoded)
        self.private_key = serialization.load_pem_private_key(private_key_bytes, passphrase)

        server_public_key_encoded = data.get("Server Public Key")

        server_public_key_bytes = b64decode(server_public_key_encoded)
        self.server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

        self.certificate = data.get("Certificate")

        key_encoded = data.get("Encryption Key")

        self.encryption_key = b64decode(key_encoded)

        self.token = data.get("Token")
            
    def make_request(self, method: Literal['GET', 'OPTIONS', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'], endpoint: str, headers: dict, **kwargs):
        """ Makes a secure request to the server by encrypting the headers being sent to the server and decrypting the data received from the server.\n

            Parameters:\n
              • method: `Literal['GET', 'OPTIONS', 'HEAD', 'POST, 'PUT', 'PATCH', 'DELETE']` (The method to make the request with)\n
              • endpoint: `str` (The endpoint to make a request to)\n
              • headers: `dict` (The headers received to send to the server)\n
            
            Example::\n
                from HTTPAuth.client import Auth as ClientAuth
                client = ClientAuth(url, session_file)
                client.auth(name, location)
                response: dict = client.make_request('GET', endpoint, headers)
        """
        
        if not self.__auth:
            err = "Client not authenticated with Server."
            raise Exception(err)
        
        symmetric_fernet = fer(self.encryption_key)

        final_headers = {}

        for key, val in headers.items():
            val_encrypted = symmetric_fernet.encrypt(val.encode())
            val_encoded = b64encode(val_encrypted)      
            final_headers.update({key: val_encoded})

        token_encoded = b64encode(self.token.encode()).decode()
        final_headers.update({"Token": token_encoded})

        response = requests.request(method=method, url=f"{self.__url}{endpoint}", headers=final_headers, **kwargs)

        status_code = response.status_code
        response_text = response.text

        if status_code != 200:
            try:
                response_dict: dict = json.loads(response_text)
                error = response_dict.get("Error")
                err = f"Error returned status code '{status_code}' with error '{error}'"
            except Exception:
                err1 = f"Server returned status code '{status_code}' with completely invalid response."
                raise Exception(err1)
            else:
                raise Exception(err)
        else:
            response_dict: dict = json.loads(response_text)
            final_response_dict = {}

            for key, val_encoded in response_dict.items():
                val_encrypted = b64decode(val_encoded)
                val = symmetric_fernet.decrypt(val_encrypted)
                try:
                    val = val.decode()
                except Exception:
                    val = val

                final_response_dict.update({key: val})
            return final_response_dict
