import hashlib, secrets

g_bits = 1024
h_bits = 512

def tech(a, i, bits):
    hls = hashlib.sha3_256()
    hls.update(a)
    b = hls.digest()

    if bits > i:
        while len(b) < bits:
            b += b
    return b[:bits // 8]

def g_tech(k): # Convert K bits to M bits
    return tech(k, 160, g_bits)

def h_tech(m): # Convert M bits to K bits
    return tech(m, 128, h_bits)

def oaep_encrypt(m):
    m_enc = m.encode()

    #apply padding technique filling out the message until it reaches 'm' size
    m_bytes = m_enc + bytes([0]*((g_bits - len(m_enc) * 8) // 8))
    m_bt_array = bytearray(m_bytes)

    #get K bits and M bits, and return both combined
    r = bytearray(secrets.token_bytes(h_bits // 8))
    m_bits = xor(m_bt_array, g_tech(r))
    k_bits = xor(r, h_tech(bytearray(m_bits)))

    return ''.join(chr(i) for i in m_bits + k_bits) #convert to str and return

def oaep_decrypt(c):
    ind = g_bits // 8
    as_ord = list(map(ord, c))
    m = as_ord[:ind]
    k = as_ord[ind:]

    r = xor(h_tech(bytearray(m)), k)
    m1 = xor(g_tech(bytearray(r)), m)
    while len(m1) != 0 and m1[-1] == 0:
        m1.pop()
    return bytearray(m1).decode()

def xor(a, b): #bitwise XOR
    return [a[i] ^ b[i] for i in range(len(a))]