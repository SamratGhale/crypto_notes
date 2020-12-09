from hashlib import sha256
from secrets import token_bytes

def keygen():
    sk = [[0 for x in range(256)] for y in range(2)]
    pk = [[0 for x in range(256)] for y in range(2)]
    for i in range(0,256):
        sk[0][i] = token_bytes(32)
        sk[1][i] = token_bytes(32)
        pk[0][i] = sha256(sk[0][i]).digest()
        pk[1][i] = sha256(sk[1][i]).digest()
    keypair={
            "sk":sk,
            "pk":pk
            }
    return keypair

def sign(m,sk):
    sig = [0 for i in range(256)]
    h = int.from_bytes(sha256(m.encode()).digest(),'little')
    for i in range(0,256):
        b = h>>i&1
        sig[i] = sk[b][i]
    return sig

def verify(m,pk,sig):
    h = int.from_bytes(sha256(m.encode()).digest(),'little')
    for i in range(0,256):
        b = h>>i&1
        check = sha256(sig[i]).digest()
        if check != pk[b][i]:
            return False
    return True

if __name__=="__main__":
    print(len(keygen()['sk'][1]))
