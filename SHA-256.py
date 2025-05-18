import hashlib

def crack_password(target_hash):
    for guess in range(100000, 1000000):  # Coba semua 6-digit (000000-999999)
        guess_str = str(guess).zfill(6)   # Format 6 digit (misal: "001234")
        guess_hash = hashlib.sha256(guess_str.encode()).hexdigest()
        if guess_hash == target_hash:
            return guess_str
    return None

# Contoh penggunaan:
target_hash = "314fba953ace15a437913e1a4d58a42219df1b617e1f1a059d8c3518c0e260a93f5077"  # Ganti dengan hash yang Anda dapatkan
password = crack_password(target_hash)

if password:
    print(f"[+] Password ditemukan: {password}")
else:
    print("[-] Password tidak ditemukan.")