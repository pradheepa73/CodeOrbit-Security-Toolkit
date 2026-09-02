"""
SAMPLE VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY
This demonstrates common security vulnerabilities for the Code Auditor
"""

import sqlite3
import os
import pickle
import subprocess
import hashlib


# ============================================
# VULNERABILITY 1: SQL Injection
# ============================================
def get_user_data(username):
    """VULNERABLE: Direct string concatenation in SQL query"""
    connection = sqlite3.connect('users.db')
    cursor = connection.cursor()
    # DANGEROUS: This allows SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


# ============================================
# VULNERABILITY 2: Hardcoded Credentials
# ============================================
SECRET_KEY = "hardcoded_secret_12345"
PASSWORD = "admin12345"
API_TOKEN = "abc123xyz456"


# ============================================
# VULNERABILITY 3: Code Injection (eval)
# ============================================
def process_code(code_snippet):
    """VULNERABLE: eval() can execute arbitrary code"""
    result = eval(code_snippet)
    return result


# ============================================
# VULNERABILITY 4: Insecure Deserialization
# ============================================
def load_data(data_file):
    """VULNERABLE: pickle can execute arbitrary code"""
    with open(data_file, 'rb') as f:
        data = pickle.load(f)
    return data


# ============================================
# VULNERABILITY 5: Command Injection
# ============================================
def run_command(command):
    """VULNERABLE: os.system executes shell commands"""
    os.system(command)


# ============================================
# VULNERABILITY 6: Missing Error Handling
# ============================================
def divide_numbers(a, b):
    """VULNERABLE: No error handling for division by zero"""
    return a / b


# ============================================
# VULNERABILITY 7: Debug Mode Enabled
# ============================================
DEBUG = True


# ============================================
# VULNERABILITY 8: Missing Input Validation
# ============================================
def process_input(user_input):
    """VULNERABLE: No input validation"""
    return user_input.upper()


# ============================================
# VULNERABILITY 9: Weak Cryptography (MD5)
# ============================================
def hash_password_md5(password):
    """VULNERABLE: Using weak hash algorithm (MD5)"""
    return hashlib.md5(password.encode()).hexdigest()


# ============================================
# VULNERABILITY 10: Insecure File Permissions
# ============================================
def save_file(filename, data):
    """VULNERABLE: Insecure file permissions"""
    with open(filename, 'w') as f:
        f.write(data)


# ============================================
# VULNERABILITY 11: Use of Insecure Random
# ============================================
import random
def generate_token():
    """VULNERABLE: Using weak random generator"""
    return str(random.randint(100000, 999999))


# ============================================
# VULNERABILITY 12: Information Disclosure
# ============================================
def get_user_info(user_id):
    """VULNERABLE: Returns too much information"""
    # This would normally query a database
    return {
        'id': user_id,
        'username': 'admin',
        'password_hash': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        'email': 'admin@example.com',
        'role': 'super_admin',
        'last_login': '2024-01-15 14:23:45',
        'ip_address': '192.168.1.100'
    }


# ============================================
# SECURE VERSIONS - How to fix these issues
# ============================================

# SECURE: SQL Injection Fix - Use parameterized queries
def get_user_data_secure(username):
    connection = sqlite3.connect('users.db')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()


# SECURE: Use environment variables for secrets
def get_secure_config():
    import os
    return {
        'secret_key': os.getenv('SECRET_KEY', ''),
        'password': os.getenv('PASSWORD', ''),
        'api_token': os.getenv('API_TOKEN', '')
    }


# SECURE: Avoid eval() - Use ast.literal_eval()
import ast
def process_code_secure(code_snippet):
    try:
        return ast.literal_eval(code_snippet)
    except:
        return "Invalid input"


# SECURE: Use proper error handling
def divide_numbers_secure(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        return "Error: Division by zero"


# SECURE: Use subprocess with proper validation
def run_command_secure(command):
    subprocess.run(command.split(), shell=False)


# SECURE: Use proper hash algorithm (bcrypt)
def hash_password_secure(password):
    import bcrypt
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)


# SECURE: Use secrets module for random generation
import secrets
def generate_token_secure():
    return secrets.token_hex(16)


# SECURE: Only return necessary information
def get_user_info_secure(user_id):
    return {
        'id': user_id,
        'username': 'admin'
    }


# SECURE: Proper debug setting
def get_debug_mode():
    import os
    return os.getenv('DEBUG', 'False').lower() == 'true'


if __name__ == "__main__":
    print("=" * 70)
    print(" SAMPLE VULNERABLE CODE - EDUCATIONAL PURPOSES")
    print("=" * 70)
    print()
    print("This file demonstrates common security vulnerabilities.")
    print("Use the Code Auditor tool to detect these issues.")
    print()
    print("Vulnerabilities demonstrated:")
    print("  1. SQL Injection")
    print("  2. Hardcoded Credentials")
    print("  3. Code Injection (eval)")
    print("  4. Insecure Deserialization (pickle)")
    print("  5. Command Injection")
    print("  6. Missing Error Handling")
    print("  7. Debug Mode Enabled")
    print("  8. Missing Input Validation")
    print("  9. Weak Cryptography (MD5)")
    print(" 10. Insecure File Permissions")
    print(" 11. Use of Insecure Random")
    print(" 12. Information Disclosure")
    print()
    print("-" * 70)
    print(" SECURE VERSIONS are provided at the bottom of this file.")
    print("-" * 70)