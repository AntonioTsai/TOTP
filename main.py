import hashlib
import hmac
import time


keys = b''
time_step = 30
t0 = 0
digits = 10


# hotp function
#   hash_mod decide the hash function to perform HMAC.
#   Option are hashlib.sha1, hashlib.sha224, hashlib.sha256, hashlib.sha384, hashlib.sha512
def hotp(key, counter, hash_mod=hashlib.sha512, length=10):
    # 8-byte counter value
    c = counter.to_bytes(8, 'big')
    hs = hmac.new(key, c, hash_mod).digest()
    offset = hs[-1] & 0xF
    bin_code = hs[offset:offset + 4]
    return (int(bin_code.hex(), 16) & 0x7FFFFFFF) % 10 ** length


def totp(key, x=30, _t0=0, hash_mod=hashlib.sha512, length=10):
    t = int((time.time() - _t0) / x)
    return str(hotp(key, t, hash_mod, length)).rjust(length, '0')


totp_value = totp(keys, time_step, t0)

print(totp_value)
