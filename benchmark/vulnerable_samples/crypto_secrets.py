"""
Cryptography and Secrets Test Case
Expected Issues: 5 high-severity issues
CWE-798: Hardcoded Credentials
CWE-327: Weak Cryptography
"""
import hashlib
import random


# Line 12: HIGH - Hardcoded API key
API_KEY = "sk_live_51HqJ2hKl3m4n5o6p7q8r9s0"

# Line 15: HIGH - Hardcoded database password
DATABASE_URL = "postgresql://admin:SuperSecret123@localhost/mydb"


def hash_password_weak(password):
    """VULNERABLE: Using MD5 for password hashing."""
    # Line 21: HIGH - Weak hashing algorithm (MD5)
    return hashlib.md5(password.encode()).hexdigest()


def generate_token_weak():
    """VULNERABLE: Using math.random for security token."""
    # Line 27: HIGH - Weak random number generator
    return str(random.randint(100000, 999999))


def encrypt_data_weak(data):
    """VULNERABLE: Hardcoded encryption key."""
    # Line 33: HIGH - Hardcoded encryption key
    SECRET_KEY = "my_secret_key_12345"
    # Simple XOR encryption (insecure)
    return ''.join(chr(ord(c) ^ ord(SECRET_KEY[i % len(SECRET_KEY)])) for i, c in enumerate(data))


# Secure versions for comparison
import secrets
from hashlib import pbkdf2_hmac


def hash_password_secure(password, salt):
    """SECURE: Uses PBKDF2 with salt."""
    return pbkdf2_hmac('sha256', password.encode(), salt, 100000)


def generate_token_secure():
    """SECURE: Uses secrets module."""
    return secrets.token_urlsafe(32)
