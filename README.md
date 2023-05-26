# HTTPAuth-Documentation
Documentation for the HTTPAuth Package.

# Introduction

The HTTPAuth package is designed to provide a secure and encrypted communication channel between a server and a local client using the HTTP protocol. Inspired by the principles of HTTPS, this package imitates its functionality to ensure confidentiality and integrity of data transmitted over an insecure network. By leveraging cryptographic algorithms and secure authentication mechanisms, HTTPAuth enables developers to establish a trusted connection between the server and client, protecting sensitive information from unauthorized access and tampering. The HTTPAuth package uses strong encryption methods to ensure that data transferred between a server and a local client cannot be accessed by a third-part.

# Precautions

While HTTPAuth enhances security within the confines of the HTTP protocol, it’s important to remember that it does not offer the same level of security as the established HTTPS standard, which provides additional safeguards against various attacks and ensures trust through certificate authorities.

A few problems yet to fixed in the HTTPAuth package are as follows:

1. Lack of Server-Side Storage Security _(Is replaceable with custom Server-Side Storage Functions)_
2. Lack of Session Management _(Planned to Fix)_
3. Limited Authentication Mechanisms _(Planned to Fix)_
4. Susceptibility to Man-in-the-middle Attacks and Impersonations

# Installation

The repository should be cloned for installation but soon will be available on pip.

# Usage

**Example 1**

server.py:

```
from flask import Flask
from HTTPAuth.server import Auth as ServerAuth
 
app = Flask(__name__)
server = ServerAuth(app=app, token_file=”./tokens.json”, server_name=”Test Server”, server_location=”US”)

server.register_auth_routes()

@server.route(rule=”/”, headers_to_accept=[‘key’], key_not_found=’return Invalid Headers to Client’, include_token=False, methods=[‘GET’])
def home(headers, *args, **kwargs):
  # Do something with the headers
  return json.dumps(data)

if __name__ == “__main__”:
  app.run()
```

client.py:

```
from HTTPAuth.client import Auth as ClientAuth

client = ClientAuth(url=”server_url”, session_file=”./session.json”)
client.auth(name=”Client”, location=”US”)

headers = {‘key’: ‘val’}

response: dict = client.make_request(method=’GET’, endpoint=”/”, headers=headers)
```

**Example 2**

server.py:

```
from flask import Flask
from HTTPAuth.server import Auth as ServerAuth
 
app = Flask(__name__)
server = ServerAuth(app=app, token_file=”./tokens.json”, server_name=”Test Server”, server_location=”US”)

server.register_auth_routes()

@server.route(rule=”/<param>”, headers_to_accept=[‘key’], key_not_found=’return Invalid Headers to Client’, include_token=False, methods=[‘GET’])
def home(headers, *args, **kwargs):
  param = kwargs['param']
  # Do something with the headers
  return json.dumps(data)

if __name__ == “__main__”:
  app.run()
```

client.py:

```
from HTTPAuth.client import Auth as ClientAuth

client = ClientAuth(url=”server_url”, session_file=”./session.json”)
client.auth(name=”Client”, location=”US”)

headers = {‘key’: ‘val’}

response: dict = client.make_request(method=’GET’, endpoint=”/value”, headers=headers)
```

# Documentation

For detailed documentation and examples, please refer to the HTTPAuth documentation at https://httpauth.readthedocs.io/en/latest/.

# License

This package is released under the MIT License. See the LICENSE file for more information.

# Contact

For any problems please contact on my discord - Ivosce#2910 or mail - ivoscev@gmail.com
