import hashlib
import hmac


# HOTP function
#   Digestmod decide the hash function to perform HMAC.
#   Option are hashlib.sha1, hashlib.sha224, hashlib.sha256, hashlib.sha384, hashlib.sha512
def hotp(key, msg, digest_mod):
    key = key.encode('ascii')
    msg = msg.encode('ascii')
    hs = hmac.new(key, msg, digest_mod).hexdigest()
    # hs = '1f8698690e02ca16618550ef7f19da8e945b555a'
    print(hs)
    print(int(hs[-1], 16))
    offset = int(hs[-1], 16) & 0xF
    p = hs[offset * 2:(offset + 4) * 2]
    print(p)
    print(int(p, 16))
    print(int(p, 16) & 0x7FFFFFFF)

keys = '1234567890'
message = 'Hello Word!'
hotp(keys, message, hashlib.sha512)
