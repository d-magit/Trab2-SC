import random, math

def rsa_encrypt(key, plaintext):
    key, n = key
    return [pow(ord(char), key, n) for char in plaintext]

def rsa_decrypt(key, cyphertext):
    key, n = key
    return ''.join(chr(pow(char, key, n)) for char in cyphertext)
    
def calc_e(z):  # calcs `e` exp to public key  1<`e`<z
    while True:
        e = random.randrange(1, z)
        if (math.gcd(e, z) == 1):
            return e

def calc_d(e, z): # Extended Euclidean Algorithm
    mod = z
    unPrev = 1
    vnPrev = 0
    unCur = 0
    vnCur = 1

    while z != 0:
        bn = e // z
        newB = e % z
        e = z
        z = newB

        # Update coefficients
        unNew = unPrev - bn * unCur
        vnNew = vnPrev - bn * vnCur

        # Shift coefficients
        unPrev = unCur
        vnPrev = vnCur
        unCur = unNew
        vnCur = vnNew

    return unPrev % mod

def generate_by_list_test(bits):
    prime_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                  31, 37, 41, 43, 47, 53, 59, 61, 67,
                  71, 73, 79, 83, 89, 97, 101, 103,
                  107, 109, 113, 127, 131, 137, 139,
                  149, 151, 157, 163, 167, 173, 179,
                  181, 191, 193, 197, 199, 211, 223,
                  227, 229, 233, 239, 241, 251, 257,
                  263, 269, 271, 277, 281, 283, 293,
                  307, 311, 313, 317, 331, 337, 347,
                  349, 353, 373, 383, 389, 397, 401]  # list of fisrt primes

    while True:
        n = random.randrange(2 ** (bits - 1) + 1, 2 ** bits - 1) # get a number in (well-filtered) interval by (bits) var value

        for p in prime_list:
            if n % p == 0 and p ** 2 <= n:
                break
        else:
            return n

def prime_miller_rabin(odd_number):  # verify if it is prime by Miller Rabin algorithm
    s = 0
    d = odd_number - 1

    while d % 2 == 0:  # find s and d
        d >>= 1
        s += 1

    def is_composite(a):  # verify if a number is probable a composite
        if pow(a, d, odd_number) == 1:
            return False
        for r in range(s):
            if pow(a, 2 ** r * d, odd_number) == odd_number - 1:
                return False
        return True

    rabin_trials = 25  # 25 trials to miller rabin test
    for i in range(rabin_trials):
        a = random.randrange(2, odd_number)  # generate a random
        if is_composite(a):  # if it is a composite number
            return False

    return True  # if pass in test (probable prime 3/4)

def get_prime():  # generate a prime
    while True:
        probable_prime = generate_by_list_test(1024)  # get a random passed in prime_list test
        if prime_miller_rabin(probable_prime):  # if this random number pass in Miller Rabin Probability test
            return probable_prime