"""
SQL Injection Test Case
Expected Issues: 3 high-severity SQL injection vulnerabilities
CWE-89: SQL Injection
"""
import sqlite3


def get_user_by_id_vulnerable(user_id):
    """VULNERABLE: String concatenation in SQL query."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Line 14: HIGH - SQL Injection via string concatenation
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()


def get_user_by_name_vulnerable(username):
    """VULNERABLE: String formatting in SQL query."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Line 24: HIGH - SQL Injection via string formatting
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


def search_users_vulnerable(search_term):
    """VULNERABLE: % formatting in SQL query."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Line 34: HIGH - SQL Injection via % formatting
    query = "SELECT * FROM users WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(query)
    return cursor.fetchall()


# Secure versions for comparison
def get_user_by_id_secure(user_id):
    """SECURE: Uses parameterized query."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
