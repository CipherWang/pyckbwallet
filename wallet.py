from ethbip44.crypto import HDPrivateKey, HDPublicKey, HDKey
from address import generateShortAddress, CODE_INDEX_SECP256K1_SINGLE, ckbhash
from Crypto.Cipher import AES
from hashlib import sha256
salt = "3820e08ad6eb90c900f2cdc76892a"

class CKBWallet:
    def __init__(self, seed : str = None):
        if not seed:
            return
        master_key = HDPrivateKey.master_key_from_mnemonic(seed)
        root_keys = HDKey.from_path(master_key,"m/44'/309'/0'")
        self.acct_priv_key = root_keys[-1]

    def getChildKey(self, change : int = 0, index : int =0):
        keys = HDKey.from_path(self.acct_priv_key,'{c}/{i}'.format(c=change, i=index))
        private_key = keys[-1]
        public_key = private_key.public_key
        sk = private_key._key.to_hex()
        pk = public_key._key.compressed_bytes.hex()
        return (sk, pk)

    def getChildAddress(self, change : int = 0, index : int =0):
        (sk, pk) = self.getChildKey(change, index)
        blake160 = ckbhash(bytes.fromhex(pk))[:40]
        ma = generateShortAddress(CODE_INDEX_SECP256K1_SINGLE, blake160, 'mainnet')
        ta = generateShortAddress(CODE_INDEX_SECP256K1_SINGLE, blake160, 'testnet')
        return (ma, ta)

    def dumpMasterKey(self, passwd : str):
        hasher = sha256((salt + passwd).encode("utf-8"))
        key = hasher.digest()[:16]
        cryptor = AES.new(key, AES.MODE_CBC, key)
        sk_hex = self.acct_priv_key.to_hex()
        count = len(sk_hex)
        if(count % 16 != 0) :
            add = 16 - (count % 16)
            sk_hex = sk_hex + ('\0' * add)
        return cryptor.encrypt(sk_hex.encode("ascii"))

    @staticmethod
    def fromEncryptedKey(passwd : str, encrypted:bytes):
        hasher = sha256((salt + passwd).encode("utf-8"))
        key = hasher.digest()[:16]
        cryptor = AES.new(key, AES.MODE_CBC, key)
        plain_text = cryptor.decrypt(encrypted).decode("ascii")
        sk_hex = plain_text.rstrip('\0')
        cw = CKBWallet()
        cw.acct_priv_key = HDPrivateKey.from_hex(sk_hex)
        return cw

if __name__ == "__main__":
    seed = "comfort rough close flame uniform chapter unique announce miracle debris space like"
    passwd = "This is a passwd"
    cw1 = CKBWallet(seed)
    ekey = cw1.dumpMasterKey(passwd)
    cw2 = CKBWallet.fromEncryptedKey(passwd, ekey)
    for i in range(10):
        print(cw1.getChildAddress(0, i))
        print(cw2.getChildAddress(0, i))