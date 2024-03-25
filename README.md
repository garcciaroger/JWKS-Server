# JWKS Server

The JWKS Server is a RESTful service developed using Python and Flask, along with a SQLite Database. It serves public keys with unique identifiers (kid) that are essential for verifying JSON Web Tokens (JWTs). This server features key expiry for enhanced security, offers an authentication endpoint, and facilitates the issuance of JWTs, including the generation of tokens with expired keys through a specific query parameter.

## Prerequisites

- Python 3.6 or higher installed on your system
- pip for installing Python packages

## Installation

### Clone the Repository

Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/jwks-server.git
cd jwks-server
```

### Set Up a Virtual Environment (Optional)

 You can create and activate a virtual environment:

```bash
python3 -m venv venv
# On Unix/Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### Install Dependencies

With the virtual environment activated, install the required dependencies:

```bash
pip install Flask cryptography pyjwt
```

## Running the Project

To launch the JWKS Server, navigate to the project directory and run:

```bash
python app.py
```


NOTE - Gradebot was runned on CSCE3550_Linux_arm64
