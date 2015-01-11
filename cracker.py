import hmac,hashlib,binascii
from hashlib import sha1
from binascii import a2b_hex, b2a_hex, unhexlify
from pbkdf2_ctypes import pbkdf2_bin


passPhrase="interwebs"
ssid        = "no place like 127.0.0.1"
A           = "Pairwise key expansion"
APmac       = a2b_hex("e091f576e83e")
Clientmac   = a2b_hex("5cac4c3b0eb2")
ANonce      = a2b_hex("44b5ab20652978b87dff9390d406e2c14f478255e867e0c3d0adbef6610f4512")
SNonce      = a2b_hex("cd186834f5465bbaa3d6c9d544dd2841785b5ff25b26c2654c7a7bd46f4f262c")
pke         = "Pairwise key expansion" + '\x00' + min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce)
data        = a2b_hex("0103007502010a00000000000000000006cd186834f5465bbaa3d6c9d544dd2841785b5ff25b26c2654c7a7bd46f4f262c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020c00")


def hmac4times(ptk, pke):
    tempPke = pke
    r = ''
    for i in range(4):
        r += hmac.new(ptk, pke + chr(i), sha1).digest()
    return r        

pmk     = pbkdf2_bin(passPhrase, ssid, 4096, 32)
ptk     = hmac4times(pmk,pke)

if ord(data[6]) & 0b00000010 == 2:
    mic     = hmac.new(ptk[0:16],data,sha1).digest()[0:16]
else:
    mic     = hmac.new(ptk[0:16],data).digest()

print "pmk:\t\t",b2a_hex(pmk),"\n"
print "ptk:\t\t",b2a_hex(ptk[0:16]),"\n"
print "mic:\t\t",b2a_hex(mic),"\n"

"""
      PMK            : DE C8 1F C0 21 76 F1 22 54 EC 88 D7 4D B1 AD 34 
                       AE 29 DB 5E 3B 9C 72 BA 70 19 36 6F 5A 3A 91 4E 

      PTK            : 86 28 53 7F 62 66 FF B3 DA 43 CB 25 0C BF 1A 81 
                       28 85 A1 6B 17 A1 FE 5A 92 A8 98 7C E3 C9 26 A0 
                       0F FE 6E D8 E2 09 61 C4 3A 2E 29 17 B3 F1 3A D0 
                       68 00 0F E2 42 C7 42 C5 5E 0E 11 82 D8 9C D7 55 

      EAPOL HMAC     : C1 5E AD 11 A5 8E 33 59 5F F3 00 60 95 1E 76 A1
"""
