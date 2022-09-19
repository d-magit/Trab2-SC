from AES import generate_key, aes_encrypt
from RSA import get_prime, calc_e, calc_d, rsa_encrypt, rsa_decrypt
from OAEP import oaep_encrypt, oaep_decrypt
import hashlib

#### Parte I: Geracao de chaves RSA
print('~~~~~ RSA Cryptosystem ~~~~~\n\tGenerating keys...\n')
p = get_prime()
q = get_prime()

n = p * q
z = (p - 1) * (q - 1)

public_key = (calc_e(z), n)
private_key = (calc_d(public_key[0], z), n)
####

#### Parte II: Cifra simetrica AES
with open('text.txt', 'r') as f:
    file_text = f.read()
    print(f'~~~~~ AES CTR Encryption ~~~~~\n\tFile text: {file_text}')

aes_key = generate_key() # Generate session key

final_msg = aes_encrypt(aes_key, file_text)

print(f'\tEncrypted message: {final_msg}')
print(f'\tAES original key: {aes_key}')

aes_key_enc = rsa_encrypt(public_key, oaep_encrypt(aes_key)) # Cifra assimetrica da chave de sessao
#print(f'~~~~~ OAEP RSA Encryption ~~~~~\n\tAES session key encrypted: {aes_key}\n')
####

#### Parte III: Assinatura
sha3 = hashlib.sha3_256()
sha3.update(file_text.encode())
msg_hash = sha3.hexdigest()
print(f'\tMessage original hash: {msg_hash}\n')
msg_hash_enc = rsa_encrypt(public_key, oaep_encrypt(msg_hash))
#print(f'~~~~~ OAEP RSA Encryption ~~~~~\n\tMessage hash encrypted: {msg_hash_enc}\n')
####

#### Parte IV: Verificacao
aes_key_dec = oaep_decrypt(rsa_decrypt(private_key, aes_key_enc))
print(f'~~~~~ OAEP RSA Decryption ~~~~~\n\tAES session key decrypted: {aes_key_dec}')
print('\tAES key ' + ('\033[1;32mMatches' if aes_key == aes_key_dec else '\033[0;31mDOES NOT Match') + '\033[0m')

msg_hash_dec = oaep_decrypt(rsa_decrypt(private_key, msg_hash_enc))
print(f'\tMessage hash decrypted: {msg_hash_dec}')
print('\tSignature ' + '\033[1;32mMatches' if msg_hash == msg_hash_dec else '\033[0;31mDOES NOT Match')
####