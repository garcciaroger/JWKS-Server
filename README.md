JWKS Server - Introduction
The JWKS Server is a RESTful service developed using Python and Flask. It serves public keys with unique identifiers (kid) that are essential for verifying JSON Web Tokens (JWTs). This server features key expiry for enhanced security, offers an authentication endpoint, and facilitates the issuance of JWTs, including the generation of tokens with expired keys through a specific query parameter.

Prerequisites
Python 3.6 or higher installed on your system
pip for installing Python packages
Installation
Clone the Repository
To get started, clone the repository to your local machine:

git clone https://github.com/yourusername/jwks-server.git
cd jwks-server


Set Up a Virtual Environment (Optional)
For a cleaner setup, you can create and activate a virtual environment:

python3 -m venv venv
# On Unix/Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

Install Dependencies
With the virtual environment activated, install the required dependencies:

pip install Flask cryptography pyjwt


Running the Project
To launch the JWKS Server, navigate to the project directory and run:

python app.py
