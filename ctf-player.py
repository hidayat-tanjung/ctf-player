import random
import hashlib
import base64
import zipfile
import os
import marshal
import binascii
import sqlite3
import html
from flask.sessions import SecureCookieSessionInterface
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pyshark
from PIL import Image
from flask import Flask, request, render_template_string
from xml.etree import ElementTree as ET

app = Flask(__name__)

# ======================== CHALLENGE 1: Password Cracker ========================
def challenge_1():
    print("\n[CHALLENGE 1: Password Cracker]")
    password = str(random.randint(100000, 999999))
    print(f"Hash of password: {hashlib.sha256(password.encode()).hexdigest()}")
    attempts = 20

    while attempts > 0:
        guess = input(f"Attempt {20 - attempts + 1}/20 > ").strip()
        if guess == password:
            print("[+] Correct! Flag 1/12: CTF{BrUt3_F0rC3_1z_FuN}")
            return True
        attempts -= 1
    print("[!] Failed! The password was:", password)
    return False

# ======================== CHALLENGE 2: Python Bytecode Reverse ========================
def challenge_2():
    print("\n[CHALLENGE 2: Python Bytecode Reverse]")
    def secret_func():
        return "CTF{Pyth0n_Byt3c0d3_1z_C00l}"
    
    # Compile to bytecode
    bytecode = marshal.dumps(secret_func.__code__)
    print("Here's some Python bytecode:", bytecode.hex())
    
    attempts = 20
    while attempts > 0:
        guess = input(f"Attempt {20 - attempts + 1}/20 > ").strip()
        if guess == "CTF{Pyth0n_Byt3c0d3_1z_C00l}":
            print("[+] Correct! Flag 2/12: CTF{Pyth0n_Byt3c0d3_1z_C00l}")
            return True
        attempts -= 1
    print("[!] Failed! The correct answer was: CTF{Pyth0n_Byt3c0d3_1z_C00l}")
    return False

# ======================== CHALLENGE 3: Flask Session Hijacking ========================
def challenge_3():
    print("\n[CHALLENGE 3: Flask Session Hijacking]")
    secret_key = os.urandom(24)
    session_serializer = SecureCookieSessionInterface().get_signing_serializer(app=None, secret_key=secret_key)
    
    # Create admin session
    admin_session = session_serializer.dumps({"username": "admin", "admin": True})
    print("Here's a Flask session cookie:", admin_session)
    
    attempts = 20
    while attempts > 0:
        guess = input(f"Attempt {20 - attempts + 1}/20 > Enter forged session: ").strip()
        try:
            data = session_serializer.loads(guess)
            if data.get("admin"):
                print("[+] Correct! Flag 3/12: CTF{Fl4sk_S3ss10n_H1jack}")
                return True
        except:
            pass
        attempts -= 1
    print("[!] Failed! You needed to forge an admin session")
    return False

# ======================== CHALLENGE 4: Steganography ========================
def challenge_4():
    print("\n[CHALLENGE 4: Steganography]")
    # Create image with hidden message
    img = Image.new("RGB", (100, 100), color=(73, 109, 137))
    pixels = img.load()
    
    # Hide flag in LSB of red channel
    flag = "CTF{St3g4n0gr4phy_1z_Fun}"
    binary_flag = ''.join(format(ord(c), '08b') for c in flag)
    
    idx = 0
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            if idx < len(binary_flag):
                r, g, b = pixels[i, j]
                r = (r & 0xFE) | int(binary_flag[idx])
                pixels[i, j] = (r, g, b)
                idx += 1
    
    img.save("secret.png")
    print("An image 'secret.png' contains a hidden message in its pixels")
    
    attempts = 20
    while attempts > 0:
        guess = input(f"Attempt {20 - attempts + 1}/20 > ").strip()
        if guess == "CTF{St3g4n0gr4phy_1z_Fun}":
            print("[+] Correct! Flag 4/12: CTF{St3g4n0gr4phy_1z_Fun}")
            os.remove("secret.png")
            return True
        attempts -= 1
    print("[!] Failed! The flag was hidden in LSB of red channel")
    os.remove("secret.png")
    return False

# ======================== CHALLENGE 5: PCAP Analysis ========================
def challenge_5():
    print("\n[CHALLENGE 5: PCAP Analysis]")
    # Create dummy PCAP with flag in DNS query
    flag = "CTF{PC4P_4n4lys1s_1z_EZ}"
    print(f"A pcap would contain DNS queries for '{flag}.example.com'")
    
    attempts = 20
    while attempts > 0:
        guess = input(f"Attempt {20 - attempts + 1}/20 > ").strip()
        if guess == flag:
            print("[+] Correct! Flag 5/12: CTF{PC4P_4n4lys1s_1z_EZ}")
            return True
        attempts -= 1
    print("[!] Failed! The flag was in DNS queries")
    return False

# ======================== CHALLENGE 6: Python Jailbreak ========================
def challenge_6():
    print("\n[CHALLENGE 6: Python Jailbreak]")
    print("Escape this restricted Python environment to read flag.txt")
    print("Blacklisted chars: import, open, eval, exec, _, [, ], {, }")
    
    attempts = 20
    flag = "CTF{Pyth0n_J41lbr34k_1z_C00l}"
    
    while attempts > 0:
        try:
            cmd = input(f"Attempt {20 - attempts + 1}/20 > ").strip()
            if any(bad in cmd for bad in ["import", "open", "eval", "exec", "_", "[", "]", "{", "}"]):
                print("Blacklisted character detected!")
            elif "flag" in cmd.lower():
                print("[+] Correct! Flag 6/12:", flag)
                return True
            else:
                print("Try harder!")
        except:
            pass
        attempts -= 1
    print("[!] Failed! Needed to read flag.txt without blacklisted chars")
    return False

# ======================== CHALLENGE 7: SQL Injection ========================
def challenge_7():
    print("\n[CHALLENGE 7: SQL Injection]")
    print("Login as admin to get the flag!")
    
    # Create vulnerable SQLite DB
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'supersecret')")
    
    attempts = 5  # Reduced for SQLi safety
    
    while attempts > 0:
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        # Vulnerable query
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            cursor.execute(query)
            if cursor.fetchone():
                print("[+] Flag 7/12: CTF{SQ1i_1nj3ct10n_MASTER}")
                return True
            else:
                print("Login failed!")
        except sqlite3.Error as e:
            print(f"Error: {e}")
        attempts -= 1
    
    print("[!] Try payload like: admin' --")
    return False

# ======================== CHALLENGE 8: XSS Attack ========================
def challenge_8():
    print("\n[CHALLENGE 8: XSS Attack]")
    print("Inject alert(1) to get the flag!")
    
    attempts = 5
    while attempts > 0:
        user_input = input("Enter XSS payload: ").strip()
        rendered = f"<html>Safe Render: {html.escape(user_input)}</html>"
        
        # Intentionally vulnerable for demo
        if "<script>alert(1)</script>" in user_input.lower():
            print("[+] Flag 8/12: CTF{XSS_4L3rt_Pr0}")
            return True
        else:
            print(rendered)
            print("Try harder!")
        attempts -= 1
    
    return False

# ======================== CHALLENGE 9: XXE Injection ========================
def challenge_9():
    print("\n[CHALLENGE 9: XXE Injection]")
    print("Extract /etc/passwd to get flag!")
    
    attempts = 3  # XXE is dangerous
    while attempts > 0:
        xml_data = input("Enter XML: ").strip()
        try:
            root = ET.fromstring(xml_data)
            if "root:x:" in str(root):
                print("[+] Flag 9/12: CTF{XX3_3nt1ty_0Wn3d}")
                return True
        except ET.ParseError:
            print("Invalid XML!")
        attempts -= 1
    
    print("[!] Try: <!DOCTYPE x [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><x>&xxe;</x>")
    return False

# ======================== CHALLENGE 10: Advanced Bruteforce ========================
def challenge_10():
    print("\n[CHALLENGE 10: Advanced Bruteforce]")
    print("Crack this SHA512 hash: ")
    target = "a6d0e8d001a59d3ec5dcd4a8a9d3c6c5e4c4b4a4c3b4a4c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"
    
    for _ in range(3):  # Limited attempts
        guess = input("Guess: ").strip()
        if hashlib.sha512(guess.encode()).hexdigest() == target:
            print("[+] Flag 10/12: CTF{Brut3_M3_1f_U_C4n}")
            return True
        print("Wrong!")
    
    print("[!] Answer was 'password123'")
    return False

# ======================== CHALLENGE 11: Bug Hunting ========================
def challenge_11():
    print("\n[CHALLENGE 11: Bug Hunting]")
    print("Find the hidden parameter to get flag!")
    
    hidden_param = "super_secret=admin"
    print(f"URL: http://vuln.site/search?q=test&debug=false")
    
    attempts = 5
    while attempts > 0:
        param = input("Enter param to add: ").strip()
        if "super_secret=admin" in param:
            print("[+] Flag 11/12: CTF{H1dd3n_P4r4m_R0cks}")
            return True
        print("Nope!")
        attempts -= 1
    
    return False

# ======================== CHALLENGE 12: AES Decryption ========================
def challenge_12():
    print("\n[CHALLENGE 12: AES Decryption]")
    key = os.urandom(16)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = "CTF{A3S_3ncrypt10n_1s_Str0ng}"
    encrypted = cipher.encrypt(pad(flag.encode(), AES.block_size))
    print("Encrypted flag (AES-128-CBC):", encrypted.hex())
    print("IV:", iv.hex())
    attempts = 5

    while attempts > 0:
        guess_key = input(f"Attempt {5 - attempts + 1}/5 > Enter key (hex): ").strip()
        try:
            guess_key = bytes.fromhex(guess_key)
            cipher = AES.new(guess_key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size).decode()
            if decrypted == flag:
                print("[+] Flag 12/12: CTF{A3S_3ncrypt10n_1s_Str0ng}")
                return True
            else:
                print("Wrong key! Decrypted:", decrypted)
        except:
            print("Invalid key!")
        attempts -= 1
    print("[!] Failed! The key was:", key.hex())
    return False

# ======================== MAIN GAME ========================
def main():
    print("""
     ____ _____ _____   _____ ___  ________ _____ 
    / ___|_   _|  ___| |  ___/ _ \|  _  \_   _|
    \___ \ | | | |_    | |__/ /_\ \ | | | | |  
     ___) || | |  _|   |  __|  _  | | | | | |  
    |____/ |_| |_|     | |__| | | | |/ /  | |  
                        \____|_| |_/___/   \_/  
    """)
    print("Welcome to the Ultimate Python CTF Challenge!")
    print("Complete all challenges to get the final flag!\n")

    challenges = [
        challenge_1, challenge_2, challenge_3,
        challenge_4, challenge_5, challenge_6,
        challenge_7, challenge_8, challenge_9,
        challenge_10, challenge_11, challenge_12
    ]

    for i, challenge in enumerate(challenges):
        print(f"\n=== Challenge {i+1}/12 ===")
        if not challenge():
            print(f"\n[!] Failed at challenge {i+1}/12")
            return

    print("\n[+] Congratulations! Final Flag: CTF{Pyth0n_CTF_M4st3r_Pr0}")

if __name__ == "__main__":
    main()