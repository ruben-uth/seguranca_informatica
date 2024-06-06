from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sqlite3

def encrypt(password):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    nonce = cipher.nonce
    return key, nonce, tag, ciphertext

def decrypt(key, nonce, tag, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

def create_user(username, password):
    key, nonce, tag, ciphertext = encrypt(password)
    
    # Armazenar dados do usuário em users.db
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                     username TEXT PRIMARY KEY,
                     nonce BLOB,
                     tag BLOB,
                     ciphertext BLOB)''')
        c.execute("INSERT INTO users VALUES (?, ?, ?, ?)",
                  (username, nonce, tag, ciphertext))
        conn.commit()
    
    # Armazenar chave em keys.db
    with sqlite3.connect('keys.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS keys (
                     username TEXT PRIMARY KEY,
                     key BLOB)''')
        c.execute("INSERT INTO keys VALUES (?, ?)", (username, key))
        conn.commit()
    
    return key

def get_user_encrypted_data(username):
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        # Recuperar dados criptografados do usuário
        c.execute("SELECT nonce, tag, ciphertext FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if row:
            nonce, tag, ciphertext = row
            with sqlite3.connect('keys.db') as conn:
                c = conn.cursor()
                # Recuperar chave de criptografia
                c.execute("SELECT key FROM keys WHERE username=?", (username,))
                key_row = c.fetchone()
                if key_row:
                    key = key_row[0]
                    return key, nonce, tag, ciphertext
        else:
            return None
        
def username_exists(username):
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                     username TEXT PRIMARY KEY,
                     nonce BLOB,
                     tag BLOB,
                     ciphertext BLOB)''')
        c.execute("SELECT 1 FROM users WHERE username=?", (username,))
        return c.fetchone() is not None
    
def delete_user(username, password):
    user_data = get_user_encrypted_data(username)
    if user_data:
        key, nonce, tag, ciphertext = user_data
        try:
            decrypted_password = decrypt(key, nonce, tag, ciphertext)
            if decrypted_password == password:
                with sqlite3.connect('users.db') as conn:
                    c = conn.cursor()
                    c.execute("DELETE FROM users WHERE username=?", (username,))
                    conn.commit()
                with sqlite3.connect('keys.db') as conn:
                    c = conn.cursor()
                    c.execute("DELETE FROM keys WHERE username=?", (username,))
                    conn.commit()
                return True
            else:
                return False
        except Exception as e:
            return False
    else:
        return False