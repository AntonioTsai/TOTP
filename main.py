import hashlib
import hmac
import time


# hotp function
#   hash_mod decide the hash function to perform HMAC.
#   Option are hashlib.sha1, hashlib.sha224, hashlib.sha256, hashlib.sha384, hashlib.sha512
def hotp(key, msg, hash_mod, length=10):
    key = str(key).encode('ascii')
    msg = str(msg).encode('ascii')
    hs = hmac.new(key, msg, hash_mod).hexdigest()
    offset = int(hs[-1], 16) & 0xF
    p = hs[offset * 2:(offset + 4) * 2]

    return (int(p, 16) & 0x7FFFFFFF) % 10 ** length


def totp(key, time_step=30, t0=0, hash_mod=hashlib.sha512, length=10):
    t = int((time.time() - t0) / time_step)

    return str(hotp(key, t, hash_mod, length)).rjust(length, '0')

keys = input('key:\n')
totp_value = totp(keys)

print(totp_value)
