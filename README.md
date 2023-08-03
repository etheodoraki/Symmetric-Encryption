# ﻿ACE414 Security of Systems and Services

### Assignment 2

Theodoraki Emmanouela 

### Implementation of AES cryptographuc algorithm in ECB mode with both 128, 256 bit modes, using OpenSSL toolkit in C.

## Tool Usage:

command:	./assign_2 -i in_file -o out_file -p password -b bits [-d | -e | -s | -v]

Options:
-i path Path to input file
-o path Path to output file
-p psswd Password for key generation
-b bits Bit mode (128 or 256 only)
-d Decrypt input and store results to output
-e Encrypt input and store results to output
-s Encrypt+sign input and store results to output
-v Decrypt+verify input and store results to output
-h This help message


## A. Key Derivation Function
First, the main function provides the password and the bits mode obtained by the 
user on build and declares the key and key_length. The function keygen(password, 
key, key_len, iv, bit_mode) generates a key based on the given password with the 
help of EVP_BytesToKey() function after setting a cipher for both cases of 
aes-128-ecb and aes-256-ecb and  the digest method is set to SHA1. The derived 
key is printed at the end in hex.

## B. Data Encryption
Input file is read and stored as “plaintext” buffer through the readFromFile 
function. The function encrypt() takes the plaintext, encrypts it with the key 
derived at Task A for aes-128-ecb and aes-256-ecb  mode and stores it to the 
ciphertext buffer using the EVP API functions:

EVP_CIPHER_CTX_new()
EVP_EncryptInit_ex()
EVP_EncryptUpdate()
EVP_EncryptFinal_ex()
EVP_CIPHER_CTX_free()

The encrypted message (ciphertext) is stored to the output file through the function writeToFile().

## C. Data Decryption
Here the implementaion of Task B is reversed. We give an encrypted message 
(ciphertext) as input file in order to decrypt it, giving the initial message 
(plaintext) and store it to an output file. Functions of EVP API used:

EVP_CIPHER_CTX_new()
EVP_DecryptInit_ex()
EVP_DecryptUpdate()
EVP_DecryptFinal_ex()
EVP_CIPHER_CTX_free()
## D. Data Signing (CMAC)
At the option of signing, input file is read for encryption and saved as 
plaintext, while the encrypted data are saved as ciphertext. Then a CMAC is 
generated through the function gen_cmac() using the functions:

CMAC_CTX_new()
CMAC_Init(ctx, key, key_len, cipher_mode, NULL)
CMAC_Update(ctx, data, data_len)
CMAC_Final(ctx, cmac, cmac_len)
CMAC_CTX_free(ctx).
Continuing, the generated CMAC and the ciphertext concatenate through the 
function concat_CMAC_cipher and the result is stored to the output file.
       
## E. Data Verification (CMAC)
In the verification stage, the input file has the concatenated CMAC and cipher 
provided by the signing. So, the input splits to obtain the ciphertext and CMAC 
separately. Since we have the ciphertext, we can now decrypt it using the 
process of Task C and obtain the plaintext. Afterwards, a new CMAC is generated 
by the process of Task D and used for comparison with the CMAC found on 
separation of the concatenated input. If the two CMACs match, the verification 
has succeeded and the plaintext can be stored to the output file. The match is 
checked through the function strcmp().
              
## F. Using the tool
1. Encryption of file “encryptme_256.txt” using the password: TUC2014030238 and 
output file name “decryptme_256.txt”.

       Key:
       79 78 F2 F9 31 4C 06 E0 B7 93 C3 5E 70 AC 08 70 
       AB 27 1B 9A 31 BC 4C 2B C4 C4 46 77 1C AA D9 54 
       Message to encrypt (plaintext): 
       Encrypt this file using  a 256-bit key.
       The key should be generated using TUC<AM> as password.
       For example, if your AM is 2020123456 the password should be TUC2020123456.

       Encrypted message (ciphertext): 
       40 19 F1 CF C7 3F E4 33 47 22 83 D8 B4 97 C5 C7 
       FC DF 52 16 63 74 0A 40 3F 6F 2D 7E E5 19 89 D6 
       19 77 01 19 ED 18 12 33 B7 30 23 E0 24 20 86 4A 
       FC A3 B9 30 A5 68 B9 29 F3 23 4F 24 DC 6A DF 50 
       0A 7A 9D 9D F6 0B BE E0 26 7F 37 40 4A CA FC 12 
       B6 F2 75 53 5F 84 7F 1A 1D 73 F4 3A AA 1D E1 4A 
       F4 F3 AB E9 86 DE E3 5D 17 DE E6 D4 02 A2 52 0E 
       F2 9C 71 8B 26 FB B3 24 B7 09 C2 ED F6 06 C7 3C 
       67 79 E5 D0 AE EE 61 CC FE 2C FE F5 07 E7 7D A8 
       89 5E 0A D6 19 E1 3C 76 69 D3 58 31 76 59 07 C6 
       08 09 B1 DA 6B 1C A1 EE 1D BC EF 22 A1 78 64 C4 


2. Decryption of file “hpy414_decryptme_128.txt” using a 128-bit key derived by 
the password “hpy414” and output filename “hpy414_encryptme_128.txt”.
           
       Key:
       8D 3B 78 B5 73 3F 18 9D 72 1A A1 52 48 6A B7 EE 
       Message to decrypt (ciphertext): 
       A7 22 4B B8 66 17 E2 A2 06 EA 33 E3 34 7E 94 1C 
       FC 61 9E 38 71 F8 66 8C 1B 88 24 15 0A 88 CC 29 
       A9 14 7E 3E FF 10 3B C4 D2 B9 9B 91 93 04 CC 15 
       7F 4E 49 7C 54 1F 16 80 2D E1 FE C0 09 6E 8E 7F 
       Decrypted message (plaintext): 
       Hello HPY414
       
       This file was encrypted with a 128-bit key
       
       BB!

3. Sgning the file “signme_128.txt” using a 128-bit key derived from the 
password TUC2014030238 and output filename to store the ciphertext concatenated 
with its CMAC in a file named “verifyme_128.txt”.

       Key:
       79 78 F2 F9 31 4C 06 E0 B7 93 C3 5E 70 AC 08 70 
       CMAC: 
       E5 51 EA F3 06 7E 19 2B 06 B7 2A B5 5B 15 8F 3A 

5. Verification of the files “hpy414_verifyme_256.txt” and 
“hpy414_verifyme_128.txt” using the appropriate key size, as the filename 
specifies. The keys derived by the password “hpy414”.


       for “hpy414_verifyme_128.txt”
       Key:
       8D 3B 78 B5 73 3F 18 9D 72 1A A1 52 48 6A B7 EE 
       CMAC1: 
       A6 18 94 13 55 F2 6B D4 77 C0 CF AF C3 B7 CD A1 
       CMAC2: 
       66 4C 57 6F 54 4B DC 7B 8E 10 FC F2 E2 4C BD B5 
       [FALSE] Verification failed. CMACs do not match.

