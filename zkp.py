import time
import Hash
import field
from random import randint
from tinyec import registry

samplecurve = registry.get_curve("brainpoolP256r1")
p = samplecurve.field.p
a = samplecurve.a
b = samplecurve.b
x_g = samplecurve.g.x
y_g = samplecurve.g.y
n = samplecurve.field.n
curve = field.Curve(a, b, p, n, x_g, y_g)

# Proof pi = (r*G, c, z) where r is random, c is the challenge, z is the proof
class Proof:
    def __init__(self, encrypted_random: field.Point, c: int, z: int):
        self.encrypted_random = encrypted_random
        self.c = c
        self.z = z
    
    def display(self):
        print("Encrypted random: ")
        self.encrypted_random.display()
        print("c = ", self.c)
        print("z = ", self.z)

def zkp_generate(secret_info: int, ID: int):
    # random r and calc r*G
    r = randint(pow(2,254), pow(2,256))
    encrypted_r = r * curve.g

    # x*G
    public_info = secret_info * curve.g

    # challenge c = H(ID,g,g^r, g^x)
    c_bytes = Hash.hash_function(str(ID) + str(curve.g.x) + str(encrypted_r.x) + str(public_info.x))
    c_int = Hash.bytes_to_long(c_bytes)
    z = r + c_int * secret_info

    return Proof(encrypted_r, c_int, z)

def zkp_verify(proof: Proof, public_info: field.Point, ID: int):
    # Read value from received proof
    receive_encrypted_r = proof.encrypted_random
    receive_c = proof.c
    receive_z = proof.z
    # check if c is calculated correctly
    if receive_c == Hash.bytes_to_long(Hash.hash_function(str(ID) + str(curve.g.x) + str(receive_encrypted_r.x) + str(public_info.x))):
        lhs = receive_z * curve.g
        rhs = receive_encrypted_r + receive_c * public_info
        # verify proof z (z*G =? r*G + c*x*G)
        if lhs == rhs:
            print("Valid proof")
            return True
    print("Invalid proof")
    return False

real_info = 345
fake_info = 344
public_info = real_info * curve.g

start = time.time()

zkproof_real = zkp_generate(real_info)
zkproof_fake = zkp_generate(fake_info)
print(zkp_verify(zkproof_real, public_info))
print(zkp_verify(zkproof_fake, public_info))

end = time.time()
duration = end - start

print("Verify duration: ", duration)
