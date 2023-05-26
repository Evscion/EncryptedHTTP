# Too lazy to write comments for explaining stuff so read the documentation.

from flask import Flask, request, make_response
from cryptography.fernet import Fernet as fer
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode, b64decode
import time
from typing import Literal
from HTTPAuth.server_utils import Server as Util_Server
from HTTPAuth.server_utils import ExtraUtils
import json

class Auth:
    """ Base class for Server-Side HTTP Authentication.\n

        This module is to be used for processing authentication requests sent by a client which uses/supports `HTTPAuth.client`
    
        Parameters:\n
              • app: `Flask` (The Flask App)\n
              • store_tokens_func: `function` = save_token (The function to store tokens.)\n
              • load_tokens_func: `function` = load_raw_data (The function to load tokens.)\n
              • token_file: str = None (Only required if `store_tokens_func` and `load_tokens_func` are not defined. The file path where the user tokens are to be stored. Must be a `.json` file)\n
              • server_name: str = 'Flask Test Server' (Name of the server)\n
              • server_location: str = 'None' (Location of the Server)\n

        Note: If a different function is assigned for `store_tokens_func`, then the function must contain one parameter which accepts the raw data. This raw data can be stored in any format as required.\n

        Note: If a different function is assigned for `load_tokens_func`, then the function must return the data in the same format and as the raw data provided. It must be a dict with the following structure:\n
                {\n
                    token: \n
                            {\n
                                'Key': key,\n
                                'Expiry': expiry\n
                            }\n
                }\n
    """
    def __init__(self, app, store_tokens_func = ExtraUtils.save_token, load_tokens_func = ExtraUtils.load_raw_data, token_file: str = None, server_name: str = "Flask Test Server", server_location: str = "None") -> None:
        """ Base class for Server-Side HTTP Authentication.\n

            Is to be used for processing authentication requests sent by a client which uses/supports `HTTPAuth.client`
        
            Parameters:\n
              • app: `Flask` (The Flask App)\n
              • store_tokens_func: `function` = save_token (The function to store tokens. Please check the documentation for more important details about this parameter.)\n
              • load_tokens_func: `function` = load_raw_data (The function to load tokens. Please check the documentation for more important details about this parameter.)\n
              • token_file: str = None (Only required if `store_tokens_func` and `load_tokens_func` are not defined. The file path where the user tokens are to be stored. Must be a `.json` file)\n
              • server_name: str = 'Flask Test Server' (Name of the server)\n
              • server_location: str = 'None' (Location of the Server)\n

            Returns:\n
              • `None`\n
        """
        self.__auth_routes = ["/auth", "/ca/get-key", "/certificate/get", "/certificate/create"]
        self.__app = app
        self.__store_tokens = store_tokens_func
        self.__load_tokens = load_tokens_func
        if store_tokens_func == ExtraUtils.save_token and load_tokens_func == ExtraUtils.load_raw_data:
            if not token_file:
                err = "When no token storage or load func is defined, token file needs to be passed in."
                raise Exception(err)
            self.__token_file = token_file
        self.__server_name: str = server_name
        self.__server_location: str = server_location
        self.__logs = False
        self.__log_file: str = None
        self.__print_logs: bool = False
    
    def update_logs(self, entry: str):
        """ Updates the logs with the given log entry.\n

            Parameters:\n
              • entry: `str` (The log entry to record)\n

            Returns:\n
              • `None`

            Example::\n
                from HTTPAuth.server import Auth as ServerAuth
                from flask import Flask
                app = Flask(__name__)
                server = ServerAuth(app=app, token_file=token_file)
                server.enable_logs(log_file=log_file, False)
                server.update_logs(entry)
        """
        if not self.__logs:
            err = "Log records have not been enabled."
            raise Exception(err)
        
        with open(self.__log_file, "r") as f:
            data = f.read()
            s = time.strftime("%d/%m/%Y - %H:%M:%S")
            if data == "":
                data += f"[{s}] : {entry}"
            else:
                data += f"\n\n[{s}] : {entry}"
        
        with open(self.__log_file, "w") as f:
            f.write(data)

    """ Base class for Server-Side Authentication """
    def register_auth_routes(self):
        """ Registers the endpoints/routes for client authentication in the server side.\n
            Is to be used for processing authentication requests sent by a client using `HTTPAuth.client`.\n

            Returns:\n
              • `None`

            Example::\n
                from flask import Flask
                from HTTPAuth.server import Auth as ServerAuth
                app = Flask(__name__)
                token_file = './tokens.json'
                server = ServerAuth(app=app, token_file=token_file)
                server.register_auth_routes()
        """
        server_name = self.__server_name
        server_location = self.__server_location

        server = Util_Server(server_name, server_location)

        server.create_certificate(server.public_key_bytes)

        tokenfile = self.__token_file

        @self.__app.route("/ca/get-key", methods=["GET"])
        def get_ca_key():
            public_key_bytes = server.ca.public_key_bytes
            public_key_encoded = b64encode(public_key_bytes).decode()

            final_result_dict = {'Public Key': public_key_encoded}

            if self.__logs:
                entry = f"CA Key requested by {request.remote_addr} on endpoint '/ca/get-key'"
                self.update_logs(entry)
                if self.__print_logs:
                    print(entry)

            return json.dumps(final_result_dict), 200
            
        @self.__app.route("/certificate/get", methods=["GET"])
        def get_cert():
            certificate_dict = server.certificate
            certificate_bytes = json.dumps(certificate_dict).encode()
            certificate_encoded = b64encode(certificate_bytes).decode()

            if self.__logs:
                entry = f"Server Certificate requested by {request.remote_addr} on endpoint '/certificate/get'"
                self.update_logs(entry)
                if self.__print_logs:
                    print(entry)
            
            final_result_dict = {'Certificate': certificate_encoded}

            return json.dumps(final_result_dict), 200

        @self.__app.route("/certificate/create", methods=["GET"])
        def create_cert():
            headers = request.headers
            public_key_encoded: str = headers.get("public_key")
            name_encoded: str = headers.get("name")
            location_encoded: str = headers.get("location")

            if not public_key_encoded or not name_encoded:
                if self.__logs:
                    entry = f"Client Certificate Creation requested by {request.remote_addr} failed due to 'Invalid Headers' on endpoint '/certificate/create'"
                    self.update_logs(entry)
                    if self.__print_logs:
                        print(entry)
                return json.dumps({'Error': 'Invalid Headers'}), 400
            
            public_key_bytes = b64decode(public_key_encoded)
            name = b64decode(name_encoded).decode()
            if not location_encoded or location_encoded == "None":
                location = "None"
            else:
                location = b64decode(location_encoded).decode()

            certificate_dict = server.ca.create_client_certificate(public_key_bytes, name, location)

            certificate_bytes = json.dumps(certificate_dict).encode()
            certificate_encoded = b64encode(certificate_bytes).decode()
            
            final_result_dict = {'Certificate': certificate_encoded}

            if self.__logs:
                entry = f"Client Certificate Creation requested by {request.remote_addr} on endpoint '/certificate/create'.\nName: {name}\nLocation: {location}"
                self.update_logs(entry)
                if self.__print_logs:
                    print(entry)

            return json.dumps(final_result_dict), 200

        @self.__app.route("/auth", methods=["POST"])
        def auth():
            headers = request.headers
            certificate_encoded = headers.get("Certificate")
            symmetric_key_encoded = headers.get("Key")

            if not certificate_encoded or not symmetric_key_encoded:
                if self.__logs:
                    entry = f"Client Certificate Creation requested by {request.remote_addr} failed due to 'Invalid Headers' on endpoint '/auth'"
                    self.update_logs(entry)
                    if self.__print_logs:
                        print(entry)
                return json.dumps({'Error': 'Invalid Headers'}), 400
            
            certificate_bytes = b64decode(certificate_encoded)
            certificate_dict = json.loads(certificate_bytes)
            r = ExtraUtils.validate_client_certificate(certificate_dict, server)

            if not r:
                if self.__logs:
                    entry = f"Client Certificate Creation requested by {request.remote_addr} failed due to 'Invalid or Expired Certificate' on endpoint '/auth'"
                    self.update_logs(entry)
                    if self.__print_logs:
                        print(entry)
                return json.dumps({'Error': 'Invalid or Expired Certificate'}), 400
            
            symmetric_key_encrypted = b64decode(symmetric_key_encoded)
            symmetric_key: bytes = server.private_key.decrypt(
                ciphertext=symmetric_key_encrypted,
                padding=padding.PKCS1v15()
            )
            if self.__load_tokens == ExtraUtils.load_raw_data:
                d: dict = self.__load_tokens(self.__token_file)
            else:
                d: dict = self.__load_tokens()
            if not ExtraUtils.validate_loaded_raw_data(d):
                err = "Invalid Loaded Raw Data"
                raise Exception(err)
            k = d.keys()
            while True:
                token = ExtraUtils.generate_session_token()
                if not token in k:
                    break
                else:
                    continue

            expiry = str(time.time() + 864000)

            raw_data: dict = ExtraUtils.form_raw_data(token, symmetric_key, expiry, self.__load_tokens, tokenfile)

            self.__store_tokens(raw_data, self.__token_file)

            token_encoded = b64encode(token.encode()).decode()

            if self.__logs:
                entry = f"Authentication requested by {request.remote_addr} on endpoint '/auth'"
                self.update_logs(entry)
                if self.__print_logs:
                    print(entry)

            return json.dumps({'Token': token_encoded}), 200

    def enable_logs(self, log_file: str, print_logs: bool = False):
        """ Enables Log records for authentication requests.\n

            Parameters:\n
              • log_file: `str` (The file path where the log records are to be stored)\n
              • print_logs: `bool` = False (Bool indicating whether the log records are to be printed or not)\n

            Returns:\n
              • `None`\n

            Example::\n
                from HTTPAuth.server import Auth as ServerAuth
                from flask import Flask
                app = Flask(__name__)
                server = ServerAuth(app=app, token_file=token_file)
                server.register_auth_routes(app, token_file, server_name, server_location)

            Warns:\n
                Logs are already enabled!
        """

        if self.__logs:
            warning = "Logs are already enabled!"
            raise Warning(warning)
        
        self.__logs = True
        self.__log_file = log_file
        self.__print_logs = print_logs

    def disable_logs(self):
        """ Enables Log records for authentication requests.\n

            Parameters:\n
              • log_file: `str` (The file path where the log records are to be stored)\n
              • print_logs: `bool` = False (Bool indicating whether the log records are to be printed or not)\n

            Returns:\n
              • `None`

            Example::\n
                from HTTPAuth.server import Auth as ServerAuth
                from flask import Flask
                app = Flask(__name__)
                server = ServerAuth(app=app, token_file=token_file)
                server.register_auth_routes(app, token_file, server_name, server_location)

            Warns:\n
                Logs are already disabled!
        """

        if not self.__logs:
            warning = "Logs are already disabled!"
            raise Warning(warning)
        
        self.__logs = False
        self.__log_file = None
        self.__print_logs = False

    def route(self, rule: str, headers_to_accept: list[str], key_not_found: Literal['set value to None', 'return Invalid Headers to Client', 'raise Exception'], include_token: bool = False, **options):
        """ Creates a Flask endpoint which decrypts the data being received by the endpoint as headers and encrypts the data being sent by the endpoint as data to the client.\n

            Parameters:\n
              • rule: `str` (The endpoint)\n
              • headers_to_accept: `list[str]` (The headers to receive and decrypt)\n
              • key_not_found: (The action to perform when a key in `headers_to_accept` is not found in the request headers)\n
                                • `set value to None`: Sets the corresponding key value to `None`\n
                                • `return Invalid Headers to Client`: Returns an `Invalid Headers 400` error to the client\n
                                • `raise Exception`: Raises an `Exception` and returns status code `500` to the client.\n
              • include_token: `bool` (Indicates whether the token is to be included in the final headers or not)\n

            Note: The view function when using `@server.route` should ALWAYS have the following three parameters:\n
                    • headers: `dict` (Contains the decrypted headers)\n
                    • *args: `tuple` (Contains the positional arguments passed to the view function when using `@app.route`)\n
                    • **kwargs: `dict` (Contains the keyword arguments passed to the view function when using `@app.route`)\n

            Note: The output of the view function of `@server.route` should always be a `dict` serialized to a `str` (preferrably using `json.dumps`). All the keys and values of the original dict should be `str`.\n

            Returns:\n
              • headers: `dict`
              • args: `tuple`
              • kwargs: `dict`
            
            Example 1::\n
                from HTTPAuth.server import Auth as ServerAuth
                from flask import Flask
                app = Flask(__name__)
                server = ServerAuth(app=app, token_file=token_file)
                server.register_auth_routes()
                @server.route(rule="/", headers_to_accept=headers_to_accept, key_not_found=Literal['set value to None', 'return Invalid Headers to Client', 'raise Exception'], include_token=include_token, methods=['GET', 'POST', ...])
                def test(headers, *args, **kwargs): # The view function always has to have the given three parameters.
                    ...
                    return json.dumps(data) #Each value of each key in the data (dict) variable should be a string.

            Example 2::\n
                from HTTPAuth.server import Auth as ServerAuth
                from flask import Flask
                app = Flask(__name__)
                server = ServerAuth(app=app, token_file=token_file)
                server.register_auth_routes()
                @server.route(rule="/<param>", headers_to_accept=headers_to_accept, key_not_found=Literal['set value to None', 'return Invalid Headers to Client', 'raise Exception'], include_token=include_token, methods=['GET', 'POST', ...])
                def test(headers, *args, **kwargs): # The view function always has to have the given three parameters.
                    param = kwargs['param']
                    ...
                    return json.dumps(data) #Each value of each key in the data (dict) variable should be a string.
        """
        def decorator_func(f):
            if rule in self.__auth_routes:
                err = f"Cant create a route with rule/route '{rule}' as it is already being used in authentication."
                raise Exception(err)
        
            @self.__app.route(rule, **options)
            def route(*args, **kwargs):
                headers = request.headers
                token_encoded = headers.get("Token")

                if not token_encoded:
                    return json.dumps({'Error': 'Invalid Headers'}), 400
                
                token = b64decode(token_encoded).decode()
                
                if self.__load_tokens == ExtraUtils.load_raw_data:
                    d: dict = self.__load_tokens(self.__token_file)
                else:
                    d: dict = self.__load_tokens()

                if not ExtraUtils.validate_loaded_raw_data(d):
                    err = "Invalid Loaded Raw Data"
                    raise Exception(err)
                
                t: dict = d.get(token)
                if not t:
                    return json.dumps({'Error': 'Invalid Token'}), 400

                expiry_str = t.get("Expiry")
                expiry = float(expiry_str)

                if time.time() > expiry:
                    return json.dumps({'Error': 'Invalid Token'}), 400
                
                symmetric_key_encoded = t.get("Key")
                symmetric_key = b64decode(symmetric_key_encoded)
                symmetric_fernet = fer(symmetric_key)
                
                final_headers = {}
                
                for key in headers_to_accept:
                    if key in headers:
                        val_encoded = headers.get(key)
                        val_encrypted = b64decode(val_encoded)
                        val = symmetric_fernet.decrypt(val_encrypted)
                        try:
                            val = val.decode()
                        except Exception:
                            val = val
                        final_headers.update({key: val})
                    else:
                        if key_not_found == 'raise Exception':
                            err = f"Key '{key}' was not found in the request headers."
                            raise Exception(err)
                        elif key_not_found == 'return Invalid Headers to Client':
                            return json.dumps({'Error': 'Invalid Headers'})
                        elif key_not_found == 'set value to None':
                            final_headers.update({key: None})

                if include_token:
                    final_headers.update({'Token': token})

                response: str = f(final_headers, *args, **kwargs)

                response: dict = json.loads(response)

                final_response = {}

                for key, val in response.items():
                    tval = str(type(val))

                    if tval == "<class 'dict'>":
                        val = json.dumps(val)
                    elif tval == "<class 'int'>":
                        val = str(val)

                    val_encrypted = symmetric_fernet.encrypt(val.encode())
                    val_encoded = b64encode(val_encrypted).decode()

                    final_response.update({key: val_encoded})

                return json.dumps(final_response), 200

            return route

        return decorator_func

if __name__ == "__main__":
    app = Flask(__name__)
    Auth.register_auth_routes(app)
    app.run(host="127.0.0.1", port=5000, debug=True)
