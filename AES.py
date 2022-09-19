import string, secrets

#AES CTR mode impl

s_box = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
         0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
         0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
         0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
         0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
         0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
         0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
         0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
         0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
         0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
         0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
         0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
         0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
         0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
         0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
         0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

def generate_key():  # key 16 bytes
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for x in range(16))

def aes_encrypt(key, plain_text):
    # Padding text
    plain_txt_list = [l for l in plain_text]
    file_len = len(plain_txt_list)
    if file_len % 16 != 0:
        plain_txt_list += ['0'] * (16 * (file_len // 16 + 1) - file_len)

    # Generate tmps
    tmp_key_lst = list_of_bytes(generate_matrix(key))
    tmp_bs_vect = list_of_bytes(generate_matrix(generate_key()))

    # Declare main vars
    counter = [[0 for x in range(4)] for x in range(4)]
    key_lst = [[0 for x in range(4)] for x in range(4)]
    plain_msg = [[0 for x in range(4)] for x in range(4)]
    base_vect = [[0 for x in range(4)] for x in range(4)]
    aux = 0

    cypher = ''
    # CTR impl
    counter_val = len(plain_txt_list) // 16 # Get counter val based on file text
    for i in range(counter_val):
        for j in range(4):
            for k in range(4):
                base_vect[j][k] = tmp_bs_vect[j][k]
                key_lst[j][k] = tmp_key_lst[j][k]
        counter[3][3] += i

        for i in range(2, 4):
            for j in range(4):
                base_vect[i][j] = counter[i][j]

        base_vect = add_round_key(key_lst, base_vect)

        for amount in range(10):
            if amount == 9:
                base_vect = sub_bytes(base_vect)
                base_vect = shift_rows(base_vect)
                key_lst = key_schedule(key_lst, amount)
                base_vect = add_round_key(key_lst, base_vect)

            else:
                base_vect = sub_bytes(base_vect)
                base_vect = shift_rows(base_vect)

                for i in range(4):
                    base_vect = mix_columns(base_vect, i)

                key_lst = key_schedule(key_lst, amount)  # amount AQ
                base_vect = add_round_key(key_lst, base_vect)
        for i in range(4):
            for j in range(4):
                plain_msg[i][j] = plain_txt_list[aux]
                aux += 1

        plain_msg = list_of_bytes(plain_msg)
        base_vect = add_round_key(plain_msg, base_vect)
        cypher += ''.join(chr(ord) for block in base_vect for ord in block)

    return cypher

def generate_matrix(key):  # matrix 128 bit
    key_lst = list(key)
    return [[key_lst.pop(0) for i in range(4)] for i in range(len(key) // 4)]

def list_of_bytes(lst):  # convert elements to byte
    return [[ord(j) for j in i] for i in lst]

def add_round_key(key_lst, txt_lst):
    for i in range(4):
        for j in range(4):
            txt_lst[i][j] = key_lst[i][j] ^ txt_lst[i][j]
    return txt_lst

def sub_bytes(lst):
    for i in range(4):
        for j in range(4):
            lst[i][j] = s_box[lst[i][j]]
    return lst

def shift_rows(lst):
    for j in range(1, 4):
        for _ in range(j):
            tmp = lst[0][j]
            lst[0][j] = lst[1][j]
            lst[1][j] = lst[2][j]
            lst[2][j] = lst[3][j]
            lst[3][j] = tmp
    return lst

def mix_columns(base_vect, i):
    def gmul(a, b):
        p = 0
        for c in range(8):
            if b & 1: p ^= a
            a <<= 1
            if a & 0x100: a ^= 0x11b
            b >>= 1
        return p
    
    w, x, y, z = (base_vect[i][0], base_vect[i][1], base_vect[i][2], base_vect[i][3])
    base_vect[i][0] = (gmul(w, 2) ^ gmul(x, 3) ^ gmul(y, 1) ^ gmul(z, 1))
    base_vect[i][1] = (gmul(w, 1) ^ gmul(x, 2) ^ gmul(y, 3) ^ gmul(z, 1))
    base_vect[i][2] = (gmul(w, 1) ^ gmul(x, 1) ^ gmul(y, 2) ^ gmul(z, 3))
    base_vect[i][3] = (gmul(w, 3) ^ gmul(x, 1) ^ gmul(y, 1) ^ gmul(z, 2))

    return base_vect

def key_schedule(tmp_key_lst, amount):
    rcon = [0x01, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00,
            0x20, 0x00, 0x00, 0x00,
            0x40, 0x00, 0x00, 0x00,
            0x80, 0x00, 0x00, 0x00,
            0x1b, 0x00, 0x00, 0x00,
            0x36, 0x00, 0x00, 0x00] #def rcon table

    new_key = [[0 for x in range(4)] for x in range(4)]

    tmp = tmp_key_lst[3][0]
    new_key[3][0] = tmp_key_lst[3][1]
    new_key[3][1] = tmp_key_lst[3][2]
    new_key[3][2] = tmp_key_lst[3][3]
    new_key[3][3] = tmp

    for j in range(4):
        new_key[3][j] = s_box[new_key[3][j]]

    for i in range(4):
        for j in range(4):
            if i == 0:
                if j == 0:
                    new_key[0][j] = tmp_key_lst[0][j] ^ new_key[3][j] ^ rcon[amount * 4]
                else:
                    new_key[0][j] = tmp_key_lst[0][j] ^ new_key[3][j]
            else:
                new_key[i][j] = tmp_key_lst[i][j] ^ new_key[i - 1][j]

    return new_key