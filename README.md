================================================================
        SECRET-KEY ENCRYPTION LAB - README
        SEED Labs | Crypto & Encryption
================================================================
 
OVERVIEW
--------
This lab explores secret-key encryption concepts including substitution
ciphers, encryption modes, padding, IV usage, and error propagation.
Tools used: Python, OpenSSL, xxd/hexdump.
 
================================================================
 
TASK 1: Frequency Analysis (Substitution Cipher)
-------------------------------------------------
Goal: Decrypt a monoalphabetic substitution cipher using frequency analysis.
 
Steps:
  1. Analyze letter frequencies in the ciphertext.
  2. Map cipher letters to plaintext letters based on English frequency tables.
  3. Apply the mapping using Python's str.maketrans() and str.translate().
  4. Save the result to plaintext.txt.
 
Key Notes:
  - Some characters with close frequencies may be mapped incorrectly.
  - Iteratively refine the mapping by reading partial plaintext for clues.
  - Useful tools: bigram/trigram frequency tables, online analyzers.
 
Sample Command (manual substitution):
  $ tr 'aet' 'XGE' < ciphertext.txt > out.txt
 
================================================================
 
TASK 2: Encryption Using Different Ciphers and Modes
-----------------------------------------------------
Goal: Encrypt a file using at least 3 different cipher types via OpenSSL.
 
Commands Used:
  AES-128-CBC:
    $ openssl enc -aes-128-cbc -e -in fayez.txt -out cipher1.bin \
      -K 00112233445566778899aabbccddeeff \
      -iv 0001020304050607080900a0b0c0d0e0f
 
  AES-128-CFB:
    $ openssl enc -aes-128-cfb -e -in fayez.txt -out cipher2.bin \
      -K 00112233445566778899aabbccddeeff \
      -iv 0001020304050607080900a0b0c0d0e0f
 
  BF-CBC (Blowfish):
    $ export OPENSSL_CONF=/etc/ssl/openssl.cnf
    $ openssl enc -bf-cbc -e -in fayez.txt -out cipher3.bin \
      -K 00112233445566778899aabbccddeeff \
      -iv 0102030405060708 \
      -provider legacy -provider default
 
Note: Output is binary ciphertext — not human-readable.
 
================================================================
 
TASK 3: ECB vs. CBC Image Encryption
-------------------------------------
Goal: Encrypt a BMP image using ECB and CBC, then compare visual output.
 
Steps:
  1. Copy original BMP and strip the header (first 54 bytes).
  2. Encrypt the data portion using ECB and CBC.
  3. Reattach the original header to view the encrypted file as an image.
 
Commands:
  $ tail -c +55 original.bmp > data_only
  $ openssl enc -aes-128-ecb -in data_only -out encrypted_ecb \
    -K 00112233445566778899aabbccddeeff -nosalt -nopad
  $ openssl enc -aes-128-cbc -in data_only -out encrypted_cbc \
    -K 00112233445566778899aabbccddeeff \
    -iv 0102030405060708090a0b0c0d0e0f10 -nosalt -nopad
  $ head -c 54 original.bmp > header
  $ cat header encrypted_ecb > encrypted_ecb.bmp
  $ cat header encrypted_cbc > encrypted_cbc.bmp
  $ eog encrypted_ecb.bmp
  $ eog encrypted_cbc.bmp
 
Observation:
  - ECB: Image structure/outline still visible — NOT secure.
    (Same plaintext block + same key = same ciphertext block)
  - CBC: Image appears as random noise — secure visual output.
    (Chaining eliminates repeating patterns)
 
================================================================
 
TASK 4: Padding
---------------
Goal: Understand PKCS#5 padding behavior in block cipher modes.
 
Part 1 - Which modes use padding?
  - ECB and CBC: YES — block ciphers require input to be a multiple
    of the block size (16 bytes for AES-128).
  - CFB and OFB: NO — these operate as stream ciphers and process
    data bit-by-bit, so no padding is needed.
 
Part 2 - Observing padding values:
  Create test files:
    $ echo -n "12345"            > A1.txt   (5 bytes)
    $ echo -n "1234567890"       > A2.txt   (10 bytes)
    $ echo -n "1234567890ABCDEF" > A3.txt   (16 bytes)
 
  Encrypt with AES-128-CBC:
    $ openssl enc -aes-128-cbc -e -in A1.txt -out A1.enc -K $KEY -iv $IV
    $ openssl enc -aes-128-cbc -e -in A2.txt -out A2.enc -K $KEY -iv $IV
    $ openssl enc -aes-128-cbc -e -in A3.txt -out A3.enc -K $KEY -iv $IV
 
  Decrypt without removing padding:
    $ openssl enc -aes-128-cbc -d -in A1.enc -out A1.dec -K $KEY -iv $IV -nopad
    $ xxd A1.dec
 
  Padding Results:
    A1 (5 bytes)  -> 11 bytes of padding added  (value: 0x0B)
    A2 (10 bytes) ->  6 bytes of padding added  (value: 0x06)
    A3 (16 bytes) -> 16 bytes of padding added  (entire extra block: 0x10)
 
================================================================
 
TASK 5: Error Propagation in Corrupted Ciphertext
--------------------------------------------------
Goal: Understand how a 1-bit corruption in the 55th byte of ciphertext
      affects decryption across different modes.
 
Setup:
  - Create a plaintext file >= 1000 bytes.
  - Encrypt using AES-128 in ECB, CBC, CFB, and OFB modes.
  - Corrupt 1 bit of the 55th byte using a hex editor or dd command.
  - Decrypt and observe the damage.
 
Results:
  ECB: 1 block lost (the corrupted block only). All other blocks recover fine.
  CBC: 2 blocks lost (corrupted block + the next block). Rest recovers fine.
  CFB: 2 blocks corrupted, then recovery resumes. Mostly recoverable.
  OFB: Only the corrupted byte(s) are lost. All other data fully recoverable.
 
================================================================
 
TASK 6: Initial Vector (IV) Issues
------------------------------------
 
--- Task 6.1: IV Must Be Unique ---
  Encrypting the same plaintext with:
    - Two different IVs  -> Two completely different ciphertexts (SECURE)
    - The same IV twice  -> Identical ciphertexts (INSECURE — reveals patterns)
 
  Conclusion: Reusing an IV under the same key leaks information about
  plaintext patterns and compromises encryption security.
 
--- Task 6.2: Known-Plaintext Attack on OFB ---
  If the same IV is reused with OFB mode, and an attacker knows one
  plaintext-ciphertext pair (P1, C1), they can recover any other message
  encrypted with the same key+IV:
 
    keystream = P1 XOR C1
    P2        = C2 XOR keystream
 
  Given:
    P1  = "This is a known message!"
    C1  = a469b1c502c1cab966965e50425438e1bb1b5f9037a4c159
    C2  = bf73bcd3509299d566c35b5d450337e1bb175f903fafc159
    P2  = "Order: Launch a missile!"
 
  If CFB were used instead: only the FIRST block of P2 would be revealed.
  OFB is not secure against known-plaintext attacks.
  CFB is considered safer in this scenario.
 
--- Task 6.3: Predictable IV Attack (Chosen-Plaintext) ---
  Scenario: Bob encrypts either "Yes" or "No". Eve knows the current IV
  and can predict the next IV Bob will use.
 
  Attack Steps:
    1. Eve sees C1 and IV1 (used on P1 = "Yes" or "No").
    2. Eve knows the next IV (IV_next) Bob will use.
    3. Eve crafts P2 = P_guess XOR IV1 XOR IV_next
       (this cancels out the IV effect, making the encryption equivalent).
    4. Eve asks Bob to encrypt P2 using IV_next -> gets C2.
    5. If C1 == C2, then P1 == P_guess. Otherwise, it's the other option.
 
  Weakness: Predictable IVs allow chosen-plaintext attacks on CBC mode.
  Fix: Always generate IVs using a cryptographically secure random number generator.
 
================================================================
 
TASK 7: Dictionary Attack on AES-128-CBC Key
---------------------------------------------
Goal: Find the encryption key given plaintext, ciphertext, and IV.
 
Known Facts:
  - Cipher: AES-128-CBC
  - Key: an English word < 16 chars, padded with '#' (0x23) to 16 bytes
  - Plaintext:  "This is a top secret."
  - Ciphertext: 764aa26b55a4da654df6b19e4bce00f4
                ed05e09346fb0e762583cb7da2ac93a2
  - IV:         aabbccddeeff00998877665544332211
 
Approach:
  1. Download an English word list.
  2. For each word, pad it with '#' to 16 bytes.
  3. Encrypt the known plaintext using AES-128-CBC with that key and IV.
  4. Compare result to the known ciphertext.
  5. Match found = encryption key discovered.
 
Compile with:
  $ gcc -o crack crack.c -lcrypto
 
================================================================
 
GENERAL OPENSSL REFERENCE
--------------------------
Encrypt:
  $ openssl enc -<cipher> -e -in plain.txt -out cipher.bin \
    -K <hex_key> -iv <hex_iv>
 
Decrypt:
  $ openssl enc -<cipher> -d -in cipher.bin -out plain.txt \
    -K <hex_key> -iv <hex_iv>
 
Hex dump:
  $ xxd file.bin
  $ hexdump -C file.bin
 
Common cipher types:
  -aes-128-ecb   -aes-128-cbc   -aes-128-cfb   -aes-128-ofb
  -aes-256-cbc   -bf-cbc        -des-cbc
 
