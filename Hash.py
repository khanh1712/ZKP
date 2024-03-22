import struct
import sys


K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def hash_function(data: bytearray) -> bytearray:

    if isinstance(data, str):
        data = bytearray(data, 'utf-8')
    elif isinstance(data, bytes):
        data = bytearray(data)
    elif not isinstance(data, bytearray):
        raise TypeError
    
    length = len(data) * 8 
    data.append(0x80)
    while (len(data) * 8 + 64) % 512 != 0:
        data.append(0x00)

    data += length.to_bytes(8, 'big') 

    assert (len(data) * 8) % 512 == 0, "Padding did not complete properly!"

    blocks = [] 
    for i in range(0, len(data), 64): 
        blocks.append(data[i:i+64])

    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h5 = 0x9b05688c
    h4 = 0x510e527f
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    for data_block in blocks:
        data_schedule = []
        for t in range(0, 64):
            if t <= 15:
                data_schedule.append(bytes(data_block[t*4:(t*4)+4]))
            else:
                term1 = _sigma1(int.from_bytes(data_schedule[t-2], 'big'))
                term2 = int.from_bytes(data_schedule[t-7], 'big')
                term3 = _sigma0(int.from_bytes(data_schedule[t-15], 'big'))
                term4 = int.from_bytes(data_schedule[t-16], 'big')
                schedule = ((term1 + term2 + term3 + term4) % 2**32).to_bytes(4, 'big')
                data_schedule.append(schedule)

        assert len(data_schedule) == 64

        
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        
        for t in range(64):
            t1 = ((h + _capsigma1(e) + _ch(e, f, g) + K[t] +
                   int.from_bytes(data_schedule[t], 'big')) % 2**32)

            t2 = (_capsigma0(a) + _maj(a, b, c)) % 2**32

            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32

        
        h0 = (h0 + a) % 2**32
        h1 = (h1 + b) % 2**32
        h2 = (h2 + c) % 2**32
        h3 = (h3 + d) % 2**32
        h4 = (h4 + e) % 2**32
        h5 = (h5 + f) % 2**32
        h6 = (h6 + g) % 2**32
        h7 = (h7 + h) % 2**32

    return ((h0).to_bytes(4, 'big') + (h1).to_bytes(4, 'big') +
            (h2).to_bytes(4, 'big') + (h3).to_bytes(4, 'big') +
            (h4).to_bytes(4, 'big') + (h5).to_bytes(4, 'big') +
            (h6).to_bytes(4, 'big') + (h7).to_bytes(4, 'big'))

def _sigma0(num: int):
    
    num = (ROTR(num, 7) ^
           ROTR(num, 18) ^
           (num >> 3))
    return num

def _sigma1(num: int):
    
    num = (ROTR(num, 17) ^
           ROTR(num, 19) ^
           (num >> 10))
    return num

def _capsigma0(num: int):
    
    num = (ROTR(num, 2) ^
           ROTR(num, 13) ^
           ROTR(num, 22))
    return num

def _capsigma1(num: int):
    
    num = (ROTR(num, 6) ^
           ROTR(num, 11) ^
           ROTR(num, 25))
    return num

def _ch(x: int, y: int, z: int):
    
    return (x & y) ^ (~x & z)

def _maj(x: int, y: int, z: int):
    
    return (x & y) ^ (x & z) ^ (y & z)

def ROTR(num: int, shift: int, size: int = 32):
    
    return (num >> shift) | (num << size - shift)


#convert bytes -> long and long -> bytes
def long_to_bytes(n, blocksize=0):

    if n < 0 or blocksize < 0:
        raise ValueError("Values must be non-negative")

    result = []
    pack = struct.pack

    # Fill the first block independently from the value of n
    bsr = blocksize
    while bsr >= 8:
        result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
        n = n >> 64
        bsr -= 8

    while bsr >= 4:
        result.insert(0, pack('>I', n & 0xFFFFFFFF))
        n = n >> 32
        bsr -= 4

    while bsr > 0:
        result.insert(0, pack('>B', n & 0xFF))
        n = n >> 8
        bsr -= 1

    if n == 0:
        if len(result) == 0:
            bresult = b'\x00'
        else:
            bresult = b''.join(result)
    else:
        # The encoded number exceeds the block size
        while n > 0:
            result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
            n = n >> 64
        result[0] = result[0].lstrip(b'\x00')
        bresult = b''.join(result)
        # bresult has minimum length here
        if blocksize > 0:
            target_len = ((len(bresult) - 1) // blocksize + 1) * blocksize
            bresult = b'\x00' * (target_len - len(bresult)) + bresult

    return bresult


def bytes_to_long(s):
    """Convert a byte string to a long integer (big endian).

    In Python 3.2+, use the native method instead::

        >>> int.from_bytes(s, 'big')

    For instance::

        >>> int.from_bytes(b'\x00P', 'big')
        80

    This is (essentially) the inverse of :func:`long_to_bytes`.
    """
    acc = 0

    unpack = struct.unpack

    # Up to Python 2.7.4, struct.unpack can't work with bytearrays nor
    # memoryviews
    if sys.version_info[0:3] < (2, 7, 4):
        if isinstance(s, bytearray):
            s = bytes(s)
        elif isinstance(s, memoryview):
            s = s.tobytes()

    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b'\x00' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc

# data = b'12345'
# if __name__ == "__main__":
#     print(hash_function(data).hex())
