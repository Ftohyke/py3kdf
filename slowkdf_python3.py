#!/usr/bin/python3

import sys
import io
import getpass
import binascii
from hashlib import sha512
import scrypt

# Maximum AES256 key length in bytes:
password_length = 32
ljust_fillchar = b'?'

def SlowKDF(password, salt, i, digest_length = password_length):
    digest = password
    for counter in range(i):
        print ("Iteration %s from %s..." % (counter+1, i) )
        digest = scrypt.hash(digest, salt, N = 2*1024*1024, r = 8, p = 2,
            buflen = digest_length if digest_length > 0 else password_length)
    return digest

read_from_file = input("Read data from files? (y/N) ")
if read_from_file.lower() == "y":
    pass_file = input("Pass location: ")
    str_pass = open(pass_file, "br")
    salt_file = input("Salt location: ")
    if salt_file != pass_file:
        str_salt = open(salt_file, "br")
    mypass = str_pass.read()
    if salt_file != pass_file:
        mysalt = str_salt.read()
        str_salt.close()
    else:
        mysalt = str_pass.read()
    str_pass.close()
else:
    first_launch = input("First time launch for this passphrase? (y/N) ")
    mypass = getpass.getpass("Passphrase: ")
    if first_launch.lower() == "y":
        if mypass != getpass.getpass("Repeat passphrase: "):
            print ("ERROR: Passwords do not match.")
            quit()
        if mypass != getpass.getpass("Repeat passphrase (again): "):
            print ("ERROR: Passphrases do not match.")
            quit()
    mysalt = input("Salt: ")
    mypass = mypass.encode()
    mysalt = mysalt.encode()

mynumber = int(input("Number of iterations: "))

buffer_length = int(input("Buffer length (0 for default length of 32 bytes): "))
buffer_length = buffer_length if buffer_length > 0 else password_length

if read_from_file.lower() != "y":
    if (len(mypass)>password_length) or (len(mysalt)>password_length):
        print ("ERROR: passphrase/salt MUST be of %s or less bytes length."
            % password_length)
        quit()
    else:
        mypass = mypass.ljust(buffer_length, ljust_fillchar)
        mysalt = mysalt.ljust(buffer_length, ljust_fillchar)

mydigest = SlowKDF(mypass, mysalt, mynumber, buffer_length)

write_to_file = input("Write binary digest to file? (y/N) ")
if write_to_file.lower() == "y":
    digest_file = input("Digest location: ")
    str_digest = open(digest_file, "bw")
    str_digest.write(mydigest)
    str_digest.close()
write_to_file = input("Write hex dump of digest to file? (y/N) ")
if write_to_file.lower() == "y":
    hexdigest_file = input("Hex dump location: ")
    str_hexdigest = open(hexdigest_file, "w")
    str_hexdigest.write(binascii.b2a_hex(mydigest).decode("utf-8"))
    str_hexdigest.close()

print ("\n == Version 1 ==")
print ("\n\nDigest in hex format:",
    binascii.b2a_hex(mydigest).decode("utf-8"))
print ("\n\nDigest in base64 format:",
    binascii.b2a_base64(mydigest).decode("utf-8"))

if read_from_file.lower() != "y":
    print ("\n == Version 2 ==")
    #mydigest_v2 = sha512(mypass+mysalt+mydigest).digest()
    mydigest_v2 = b'';
    for i in range(buffer_length):
        mydigest_v2 += (mypass[i]^mysalt[i]^mydigest[i]).to_bytes(1, sys.byteorder)
    mydigest_v2 = sha512(mydigest_v2).digest()
    print ("\n\nVersion 2 digest in hex format:",
        binascii.b2a_hex(mydigest_v2).decode("utf-8"))
    print ("\n\nVersion 2 digest in base64 format:",
        binascii.b2a_base64(mydigest_v2).decode("utf-8"))
    print ("\n == Version 1^2 ==")
    #mydigest_v1plus2=mydigest+mydigest_v2
    mydigest_v1xor2 = b'';
    for i in range(buffer_length):
        mydigest_v1xor2 += (mydigest[i]^mydigest_v2[i]).to_bytes(1, sys.byteorder)
    mydigest_v1xor2 = sha512(mydigest_v1xor2).digest()
    print ("\n\nVersion 1^2 digest in hex format:",
        binascii.b2a_hex(mydigest_v1xor2).decode("utf-8"))
    print ("\n\nVersion 1^2 digest in base64 format:",
        binascii.b2a_base64(mydigest_v1xor2).decode("utf-8"))
