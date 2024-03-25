JWKS-Server

Introduction

The JWKS-Server is a RESTful service developed using Python and Flask. It is designed to provide public keys with unique identifiers (kid) that can be used for verifying JSON Web Tokens (JWTs). This server implements key expiry for enhanced security, includes an authentication endpoint, and handles the issuance of JWTs, including those with expired keys based on a query parameter. 

Prerequisites


Python 3.6 or higher installed on your system
pip for installing Python packages
Installation

Clone the Repository
First, clone the repository to your local machine:

git clone https://github.com/yourusername/jwks-server.git
cd jwks-server

Set Up a Virtual Environment (Optional)
To create and activate a virtual environment, run:

python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`

Install Dependencies
With your virtual environment activated, install the project dependencies:
pip install Flask cryptography pyjwt

Running the Project
To run the JWKS-Server, navigate to the project directory and execute the following command:

python app.py
This command starts the Flask development server, and the JWKS-Server will be accessible at http://127.0.0.1:8080.

Usage
Authentication Endpoint
To issue a JWT, make a POST request to the /auth endpoint. You can specify if you want an expired token by including the expired query parameter:

POST http://127.0.0.1:8080/auth?expired=true

JWKS Endpoint
To retrieve the public keys in JWKS format, access the /.well-known/jwks.json endpoint:

arduino
Copy code
GET http://127.0.0.1:8080/.well-known/jwks.json
