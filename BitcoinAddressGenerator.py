

import argparse
import os
import binascii
import ecdsa
import hashlib




# Range of valid private keys is governed by the secp256k1 ECDSA standard used by Bitcoin: any 256-bit number from 0x1 to 0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140 is a valid private key.
def generateKey(bits=256):
    assert bits % 8 == 0
    return makeBinaryKeyReadableHexString(os.urandom(int(bits/8)))

#mak
def makeBinaryKeyReadableHexString(abinary):
    hex_binary = binascii.hexlify(abinary)
    return hex_binary.decode('utf-8')

def privateKeyToPublicKey(private_key):
    private_key = binascii.unhexlify(private_key)
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    return ('04' + binascii.hexlify(sk.verifying_key.to_string()).decode('utf-8'))


#IMPORTANT any implmentation must make sure 00 bytes on front are not clipped here when encoding or getting hash!
#IMPORTANT Hash result should be bigEndian?
def getAddressFromPublicKey(public_key, version_byte = '00'):
    hash_object = hashlib.new('ripemd160')
    hash_object.update(hashlib.sha256( binascii.unhexlify(public_key.encode() ) ).digest())
    address = (version_byte + hash_object.hexdigest())
    address = address + getCheckSum(address)
    return address

#get 4 byte double sha256 checksum of hex string
def getCheckSum(astring):
    doublehash = hashlib.sha256( hashlib.sha256( binascii.unhexlify(astring.encode()) ).digest() ).hexdigest()
    return doublehash[0:8]

#wif_version_byte byte '80' if mainnet, 'ef' if if testnet,
#type_pub is '01' if key corresponds to commpressed public key, empty otherwise
def privKeyToWIF(astring, wif_version_byte = '80', type_pub = ''):
    wif = wif_version_byte + astring + type_pub
    wif = wif + getCheckSum(wif)
    return base58CheckEncoding(wif)

# def wifToRawKey(astring):
    #todo

#IMPORTANT any implmentation must make sure 00 bytes on front are not clipped here when encoding or getting hash!
def base58CheckEncoding(astring):
    alphabet = b58_alphabet
    leading_zeros = countLeadingZeroBytes(astring)

    n = int(astring, 16)
    output = []
    while n > 0 :
        n, reminder = divmod (n, 58)
        output.append(alphabet[reminder])

    count = 0
    while count < leading_zeros:
        output.append(alphabet[0])
        count += 1

    output = ''.join(output[::-1])
    return output


def countLeadingZeroBytes(astring):

    char_to_count = '0'
    count = 0
    for achar in astring:
        if achar != char_to_count:
            break
        count += 1

    return (count//2)

#----------------------
#----------------------




#---------------------
#---------------------

b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

#
# Lets now generate key
key_length = 256

#type of Bitcoin address 0x00 is P2PKH mainnet (string type)
version_byte = '00'

#wif_version_byte byte '80' if mainnet, 'ef' if if testnet,
wif_version_byte = '80'

#type_pub is '01' if key corresponds to commpressed public key, empty otherwise
type_pub = ''




parser = argparse.ArgumentParser()
parser.add_argument('--privateKeyLength', help='bytes for private key length', type=int)
parser.add_argument('--encode', help='base58check encode hex string')
parser.add_argument('--toWif', help='Convert private key hex string to WIF format')
args = parser.parse_args()

if args.privateKeyLength:
    print("length given: ", args.privateKeyLength)

if args.encode:
    print(base58CheckEncoding(args.encode))
    exit()

if args.encode:
    print(base58CheckEncoding(args.encode))
    exit()

if args.toWif:
    print( privKeyToWIF(args.toWif, wif_version_byte, type_pub) )
    exit()




private_key = generateKey(key_length)
#private_key = makeBinaryKeyReadableHexString(private_key_binary)
print('Private-Key:\n ', private_key)

print('\nPrivate-Key WIF format (uncommpressed pubkey):\n', privKeyToWIF(private_key, wif_version_byte, type_pub))

public_key = privateKeyToPublicKey(private_key)

print('\nPublic-key:\n', public_key)

address = getAddressFromPublicKey(public_key, version_byte)
print('\nBitcoin Address as hex, unencoded:\n', address)

address_encoded = base58CheckEncoding(address)

print('\nBase58Check encoded address:\n', address_encoded)
