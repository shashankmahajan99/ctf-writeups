from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import re
import requests

DEBUG_COOKIE = 'camchito'

url = 'https://web-crypto.1337.sb/collection'
headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'cookie': f'DEBUG={DEBUG_COOKIE}',
    'origin': 'https://web-crypto.1337.sb',
    'priority': 'u=0, i',
    'referer': 'https://web-crypto.1337.sb/',
    'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Linux"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
}

data = {
    'secret': 'flag'
}

response = requests.post(url, headers=headers, data=data)

def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
    except ValueError:
        return None
    
def brute_force(ciphertext):
    for i in range(256):
        key = bytes([i]*32)
        for j in range(256):
            iv = bytes([j]*16)
            plaintext = decrypt(ciphertext, key, iv)
            if plaintext is not None:
                plaintext_str = plaintext.decode('utf-8', 'ignore')
                print(f"Key: {i}, IV: {j}, Plaintext: {plaintext_str}")
                if re.match(r'cr3{.*}', plaintext_str):
                    print(f"\n\n\nFound Flag: {plaintext_str}\n\n\n")

def main():
    # Extract the ciphertext from the response
    ciphertext = base64.b64decode(response.json()["data"])
    brute_force(ciphertext)

if __name__ == "__main__":
    main()