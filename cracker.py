import hmac,hashlib,binascii
from hashlib import sha1
from binascii import a2b_hex, b2a_hex, unhexlify
from pbkdf2_ctypes import pbkdf2_bin


passPhrase="interwebs"
ssid        = "no place like 127.0.0.1"
A           = "Pairwise key expansion"
APmac       = a2b_hex("e091f576e83e")
Clientmac   = a2b_hex("7cdd90563086")
ANonce      = a2b_hex("44b5ab20652978b87dff9390d406e2c14f478255e867e0c3d0adbef6610f44f3")
SNonce      = a2b_hex("49e1e94790113ba9822b6b83b65558376463e361831f69943fffa2f603a2ecdb")
B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce)
data        = a2b_hex("0103007502010a0000000000000000000049e1e94790113ba9822b6b83b65558376463e361831f69943fffa2f603a2ecdb0000000000000000000000000000000000000000000000000000000000000000")

def customPRF512(key,A,B):
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]


pmk     = pbkdf2_bin(passPhrase, ssid, 4096, 32)
ptk     = customPRF512(pmk,A,B)
mic     = hmac.new(ptk[0:16],data)

print "pmk:\t\t",b2a_hex(pmk),"\n"
print "ptk:\t\t",b2a_hex(ptk[0:16]),"\n"
print "mic:\t\t",mic.hexdigest(),"\n"
