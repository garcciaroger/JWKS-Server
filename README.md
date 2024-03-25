# JWKS Server

The JWKS Server is a RESTful service developed using Python and Flask, accompanied by a SQLite Database. It provides public keys with unique identifiers (kid) crucial for verifying JSON Web Tokens (JWTs). This server is designed with key expiry features for improved security, includes an authentication endpoint, and supports the issuance of JWTs. It even allows for the generation of tokens with expired keys through a specific query parameter.

## Prerequisites

- Python 3.6 or higher installed on your system
- pip for installing Python packages

## Installation

### Clone the Repository

To get started, clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/jwks-server.git
cd jwks-server



python3 -m venv venv
# On Unix/Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate


pip install Flask cryptography pyjwt

python app.py
