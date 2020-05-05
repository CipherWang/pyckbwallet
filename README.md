# pyckbwallet
ckb wallet python lib

## usage

### Create CKB HD wallet

```py
seed = "comfort rough close flame uniform chapter unique announce miracle debris space like"
cw = CKBWallet(seed)
for i in range(10):
    # get child address
    print(cw.getChildAddress(0, i))
    # get child key
    cw.getChildKey(0, i)
```

### Dump / restore HD wallet.
Master key is encrypted by AES-128

```py
ekey = cw.dumpMasterKey(passwd)
cw = CKBWallet.fromEncryptedKey(passwd, ekey)
```