import json
import base64
import binascii
from os.path import exists
from sys import setrecursionlimit

from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def get_encrypted_keys(filename):
    """
    Parse data from packets sent to attacker
    """

    with open(filename, "rb") as f:
        packets_raw = f.read()
    packets = json.loads(packets_raw)

    keys = []

    for packet in packets:
        packet_data = packet['_source']['layers']['data']
        bytes = packet_data['data.data'].split(':')

        data = bytearray()
        for byte in bytes:
            data.append(unhex(byte))

        keys.append(data)

    return keys


class Decrypter:

    MAGIC = 0xBEE4FAC3

    def _decrypt_header(self, filename, input_file, key):
        iv = input_file.read(AES.block_size)

        if len(iv) < AES.block_size:
            raise Exception("Invalid file {0}".format(filename))

        ctr = Counter.new(AES.block_size * 8, initial_value=long(binascii.hexlify(iv), 16))
        aes = AES.new(key, mode=AES.MODE_CTR, counter=ctr)

        data = input_file.read(AES.block_size)

        if len(data) < AES.block_size:
            raise Exception("Invalid file {0}".format(filename))

        data = aes.decrypt(data)
        if long(binascii.hexlify(data[:4]), 16) != self.MAGIC:
            raise Exception("Invalid file {0}".format(filename))

        lsize = struct.calcsize('<I')
        l = struct.unpack('<I', data[4:4 + lsize])[0]
        filename = str(data[4 + lsize:])
        filename = filename[:l]
        while len(filename) < l:
            data = input_file.read(AES.block_size)
            filename += aes.decrypt(data)
            filename = filename[:l]

        return (aes, filename)

    def _decrypt_file(self, path, filename, key):
        input_filename = os.path.join(path, filename)
        with open(input_filename, 'rb') as input_file:
            aes, output_filename = self._decrypt_header(filename, input_file, key)

            output_filename = os.path.join("decrypted_files/", output_filename)
            with open(output_filename, 'wb') as output_file:
                while True:
                    data = input_file.read(AES.block_size)
                    if len(data) == 0:
                        break
                    output_file.write(aes.decrypt(data))

            log.info("Saved " + output_filename)

    def process(self, path, digest_key_list):
        lookup = dict(digest_key_list)
        lookup.update(dict((digest[:32], key) for digest, key in digest_key_list))

        for dirpath, _, filenames in os.walk(path):
            for filename in filenames:
                try:
                    key = lookup[filename[1:-7]]
                    self._decrypt_file(dirpath, filename, base64.b64decode(key))
                except KeyError:
                    continue


class Hack:

    decrypter = None

    n = None
    key = None

    def __init__(self, pub_pem, c1, c2):
        self.decrypt_key(pub_pem, c1, c2)
        self.decrypter = Decrypter()

    def decode_key(self, key):
        return base64.b64decode(key)

    def decrypt_key(self, pub_pem, c1, c2):
        pub_key = RSA.importKey(pub_pem)
        self.n = pub_key.n
        c1 = bytes_to_long(self.decode_key(c1))
        c2 = bytes_to_long(self.decode_key(c2))

        self.key = (c2 + 2*c1 - 1) * modinv(c2 - c1 + 2, self.n) % self.n
        log.info("Hack.init m: " + str(long_to_bytes(self.key)))

    def next_key(self):
        k = long_to_bytes(self.key)
        self.key += 1
        return k

    def decrypt(self, key):
        digest = SHA256.new(key).digest()
        digest = binascii.hexlify(digest)
        filename = digest[:32]

        p = log.progress("Decrypting " + str(filename))

        decrypted_key = self.next_key()
        p.status("decrypting file (AES)")

        key = SHA256.new(decrypted_key).digest()
        key = base64.b64encode(key)

        self.decrypter.process("encrypted_files/", [(str(digest), key)])

        p.success()


if __name__ == "__main__":
    setrecursionlimit(1500)

    log.info("Retrieving keys from packets.")
    encrypted_keys = get_encrypted_keys("packets/packets.json")

    log.info("Loading RSA public key.")
    pub_pem = read("keys/pub.pem")

    log.info("Preparing to decrypt files.")
    hack = Hack(pub_pem, encrypted_keys[0], encrypted_keys[1])
    for k in encrypted_keys:
        hack.decrypt(k)

