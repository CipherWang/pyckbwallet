# CKB Address test code
# cipher@nervos.org


import segwit_addr as sa
import hashlib
import unittest

def ckbhash(msg):
    hasher = hashlib.blake2b(digest_size=32, person=b'ckb-default-hash')
    hasher.update(msg)
    return hasher.hexdigest()

FORMAT_TYPE_SHORT     = 0x01
FORMAT_TYPE_FULL_DATA = 0x02
FORMAT_TYPE_FULL_TYPE = 0x04

CODE_INDEX_SECP256K1_SINGLE = 0x00
CODE_INDEX_SECP256K1_MULTI  = 0x01

def generateShortAddress(code_index, args, network = "mainnet"):
    """ generate a short ckb address """
    hrp = {"mainnet": "ckb", "testnet": "ckt"}[network]
    hrpexp =  sa.bech32_hrp_expand(hrp)
    format_type  = FORMAT_TYPE_SHORT
    payload = bytes([format_type, code_index]) + bytes.fromhex(args)
    data_part = sa.convertbits(payload, 8, 5)
    values = hrpexp + data_part
    polymod = sa.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    combined = data_part + checksum
    addr = hrp + '1' + ''.join([sa.CHARSET[d] for d in combined])
    return addr

def generateFullAddress(hash_type, code_hash, args, network = "mainnet"):
    format_type = {"Data" : bytes([FORMAT_TYPE_FULL_DATA]),
                 "Type" : bytes([FORMAT_TYPE_FULL_TYPE])}[hash_type]
    hrp = {"mainnet": "ckb", "testnet": "ckt"}[network]
    hrpexp =  sa.bech32_hrp_expand(hrp)
    payload = bytes(format_type) + bytes.fromhex(code_hash)
    payload += bytes.fromhex(args)
    data_part = sa.convertbits(payload, 8, 5)
    values = hrpexp + data_part
    polymod = sa.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    combined = data_part + checksum
    addr = hrp + '1' + ''.join([sa.CHARSET[d] for d in combined])
    return addr


def decodeAddress(addr, network = "mainnet"):
    hrp = {"mainnet": "ckb", "testnet": "ckt"}[network]
    hrpgot, data = sa.bech32_decode(addr)
    if hrpgot != hrp or data == None:
        return False
    decoded = sa.convertbits(data, 5, 8, False)
    if decoded == None:
        return False
    payload = bytes(decoded)
    format_type = payload[0]
    if format_type == FORMAT_TYPE_SHORT:
        code_index = payload[1]
        pk = payload[2:].hex()
        return ("short", code_index, pk)
    elif format_type == FORMAT_TYPE_FULL_DATA or format_type == FORMAT_TYPE_FULL_TYPE:
        full_type = {FORMAT_TYPE_FULL_DATA:"Data", FORMAT_TYPE_FULL_TYPE:"Type"}[format_type]
        ptr = 1
        code_hash = payload[ptr : ptr+32].hex()
        ptr += 32
        args = payload[ptr :].hex()
        return ("full", full_type, code_hash, args)