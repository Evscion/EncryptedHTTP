.. HTTPAuth documentation master file, created by
   sphinx-quickstart on Fri May 26 14:22:42 2023.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to the Documentation for HTTPAuth
====================================

Introduction
------------

The HTTPAuth package is designed to provide a secure and encrypted communication channel between a server and a local client using the HTTP protocol. Inspired by the principles of HTTPS, this package imitates its functionality to ensure confidentiality and integrity of data transmitted over an insecure network.
By leveraging cryptographic algorithms and secure authentication mechanisms, HTTPAuth enables developers to establish a trusted connection between the server and client, protecting sensitive information from unauthorized access and tampering.
The HTTPAuth package uses strong encryption methods to ensure that data transferred between a server and a local client cannot be accessed by a third-part.

Precautions
-----------

HTTPAuth provides a quick and straightforward way to secure web applications during development. However, it is essential to highlight that using HTTPAuth for development purposes is not recommended due to inherent security vulnerabilities. This brief will outline the key reasons why HTTPAuth is considered insecure and the potential risks associated with its usage.

1. Lack of Proper Encryption
2. Lack of Server-Side Storage Security (Is replaceable with a custom Server-Side Storage Functions)
3. Lack of Session Management (Planned to Fix)
4. Limited Authentication Mechanisms
5. Susceptibility to Man-in-the-middle Attacks and Impersonations

Considering the aforementioned security risks, it is strongly advised not to rely solely on HTTPAuth for development purposes. While it may provide a convenient way to secure applications during initial stages, it should never be used in production environments. 

Note: While HTTPAuth enhances security within the confines of the HTTP protocol, it's important to remember that it does not offer the same level of security as the established HTTPS standard, which provides additional safeguards against various attacks and ensures trust through certificate authorities.


Installation
------------

   $ pip install HTTPAuth

Usage
-----

server.py:

   from flask import Flask
   from HTTPAuth.server import Auth as ServerAuth

   app = Flask(__name__)
   server = ServerAuth(app=app, token_file="./tokens.json", server_name="Test Server", server_location="US")

   server.register_auth_routes()

   @server.route(rule="/", headers_to_accept=['key'], key_not_found='return Invalid Headers to Client', include_token=False, methods=['GET'])
   def home(headers, *args, **kwargs):
      # Do something with the headers
      return json.dumps(data)

   if __name__ == "__main__":
      app.run()

client.py:
   from HTTPAuth.client import Auth as ClientAuth

   client = ClientAuth(url="*server_url*", session_file="./session.json")
   client.auth(name="Client", location="US")

   headers = {'key': 'val'}

   response: dict = client.make_request(method='GET', endpoint="/", headers=headers)


Contents
==================

.. toctree::
   :maxdepth: 2
   :caption: Package:

   HTTPAuth



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
