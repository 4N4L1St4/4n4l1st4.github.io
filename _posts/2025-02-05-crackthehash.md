---
title: "TryHackMe: Crack the hash"
description: Esta máquina permite praticar hacking de aplicações web e escalada de privilégios.
author: c3n0r4
categories: [Challenges, Linux]
tags: [CTF-Fácil, name-that-hash, hashcat, john-the-ripper, rainbow-tables, hashes.com]
media_subpath: /assets/images/crackthehash
image:
  path: capa.webp
comments: true
---


Para este desafio, utilizei o identificador de hash `Name-That-Hash` e as ferramentas `John the Ripper` e `Hashcat` para a quebra dos hashes.

Antes de começar a quebra dos hashes é necessario identificar cada tipo, então fiz toda a enumeração primeiro.

## Identificando hashes

```console
┌──(thm)─(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ nth -t "48bb6e862e54f2a795ffc4e541caed4d"                                                   
  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 
    

48bb6e862e54f2a795ffc4e541caed4d

Most Likely 
MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
MD4, HC: 900 JtR: raw-md4
NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
Domain Cached Credentials, HC: 1100 JtR: mscach

Least Likely
Domain Cached Credentials 2, HC: 2100 JtR: mscach2 Double MD5, HC: 2600  Tiger-128,  Skein-256(128),  Skein-512(128),  Lotus Notes/Domino 5, HC: 8600 JtR: lotus5 md5(md5(md5($pass))), HC: 3500 
Summary: Hashcat mode is only supported in hashcat-legacy. md5(uppercase(md5($pass))), HC: 4300  md5(sha1($pass)), HC: 4400  md5(utf16($pass)), JtR: dynamic_29 md4(utf16($pass)), JtR: dynamic_33 
md5(md4($pass)), JtR: dynamic_34 Haval-128, JtR: haval-128-4 RIPEMD-128, JtR: ripemd-128 MD2, JtR: md2 Snefru-128, JtR: snefru-128 DNSSEC(NSEC3), HC: 8300  RAdmin v2.x, HC: 9900 JtR: radmin Cisco 
Type 7,  BigCrypt, JtR: bigcrypt 
                                                                                                
┌──(thm)─(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ nth -t "CBFDAC6008F9CAB4083784CBD1874F76618D2A97" --no-banner

CBFDAC6008F9CAB4083784CBD1874F76618D2A97

Most Likely 
SHA-1, HC: 100 JtR: raw-sha1 Summary: Used for checksums.See more
HMAC-SHA1 (key = $salt), HC: 160 JtR: hmac-sha1
Haval-128, JtR: haval-128-4
RIPEMD-128, JtR: ripemd-128

Least Likely
Double SHA-1, HC: 4500  RIPEMD-160, HC: 6000 JtR: ripemd-160 Haval-160 (3 rounds), HC: 6000 JtR: dynamic_190 Haval-160 (4 rounds), HC: 6000 JtR: dynamic_200 Haval-160 (5 rounds), HC: 6000 JtR: 
dynamic_210 Haval-192 (3 rounds), HC: 6000 JtR: dynamic_220 Haval-192 (4 rounds), HC: 6000 JtR: dynamic_230 Haval-192 (5 rounds), HC: 6000 JtR: dynamic_240 Haval-224 (4 rounds), HC: 6000 JtR: 
dynamic_260 Haval-224 (5 rounds), HC: 6000 JtR: dynamic_270 Haval-160,  Tiger-160,  HAS-160,  LinkedIn, HC: 190 JtR: raw-sha1-linkedin Summary: Hashcat mode is only supported in oclHashcat. 
Skein-256(160),  Skein-512(160),  MangosWeb Enhanced CMS,  sha1(sha1(sha1($pass))), HC: 4600 Summary: Hashcat mode is only supported in hashcat-legacy. sha1(md5($pass)), HC: 4700  
sha1($pass.$salt), HC: 110  sha1($salt.$pass), HC: 120  sha1(unicode($pass).$salt), HC: 130  sha1($salt.unicode($pass)), HC: 140  HMAC-SHA1 (key = $pass), HC: 150 JtR: hmac-sha1 
sha1($salt.$pass.$salt), HC: 4710  MySQL5.x, HC: 300 JtR: mysql-sha1 MySQL4.1, HC: 300 JtR: mysql-sha1 Cisco Type 7,  BigCrypt, JtR: bigcrypt 
                                                                                                
┌──(thm)─(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ nth -t "1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032" --no-banner

1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032

Most Likely 
SHA-256, HC: 1400 JtR: raw-sha256 Summary: 256-bit key and is a good partner-function for AES. Can be used in Shadow files.
Keccak-256, HC: 17800 
Haval-128, JtR: haval-128-4
Snefru-256, JtR: snefru-256

Least Likely
RIPEMD-256, JtR: dynamic_140 Haval-256 (3 rounds), JtR: dynamic_140 Haval-256 (4 rounds), JtR: dynamic_290 Haval-256 (5 rounds), JtR: dynamic_300 GOST R 34.11-94, HC: 6900 JtR: gost GOST CryptoPro
S-Box,  Blake2b-256,  SHA3-256, HC: 17400 JtR: dynamic_380 PANAMA, JtR: dynamic_320 BLAKE2-256,  BLAKE2-384,  Skein-256, JtR: skein-256 Skein-512(256),  Ventrilo,  sha256($pass.$salt), HC: 1410 
JtR: dynamic_62 sha256($salt.$pass), HC: 1420 JtR: dynamic_61 sha256(sha256($pass)), HC: 1420 JtR: dynamic_63 sha256(sha256_raw($pass))), HC: 1420 JtR: dynamic_64 sha256(sha256($pass).$salt), HC: 
1420 JtR: dynamic_65 sha256($salt.sha256($pass)), HC: 1420 JtR: dynamic_66 sha256(sha256($salt).sha256($pass)), HC: 1420 JtR: dynamic_67 sha256(sha256($pass).sha256($pass)), HC: 1420 JtR: 
dynamic_68 sha256(unicode($pass).$salt), HC: 1430  sha256($salt.unicode($pass)), HC: 1440  HMAC-SHA256 (key = $pass), HC: 1450 JtR: hmac-sha256 HMAC-SHA256 (key = $salt), HC: 1460 JtR: hmac-sha256
Cisco Type 7,  BigCrypt, JtR: bigcrypt 
                                                                                                
┌──(thm)─(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ nth -t "$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom" --no-banner

y
No hashes found.
                                                                                                
┌──(thm)─(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ nth -t "279412f945939ba78ce0758d3fd83daa" --no-banner

279412f945939ba78ce0758d3fd83daa

Most Likely 
MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
MD4, HC: 900 JtR: raw-md4
NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
Domain Cached Credentials, HC: 1100 JtR: mscach

Least Likely
Domain Cached Credentials 2, HC: 2100 JtR: mscach2 Double MD5, HC: 2600  Tiger-128,  Skein-256(128),  Skein-512(128),  Lotus Notes/Domino 5, HC: 8600 JtR: lotus5 md5(md5(md5($pass))), HC: 3500 
Summary: Hashcat mode is only supported in hashcat-legacy. md5(uppercase(md5($pass))), HC: 4300  md5(sha1($pass)), HC: 4400  md5(utf16($pass)), JtR: dynamic_29 md4(utf16($pass)), JtR: dynamic_33 
md5(md4($pass)), JtR: dynamic_34 Haval-128, JtR: haval-128-4 RIPEMD-128, JtR: ripemd-128 MD2, JtR: md2 Snefru-128, JtR: snefru-128 DNSSEC(NSEC3), HC: 8300  RAdmin v2.x, HC: 9900 JtR: radmin Cisco 
Type 7,  BigCrypt, JtR: bigcrypt 
                                                                                                
┌──(thm)─(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ nth -t "F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85" --no-banner

F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85

Most Likely 
SHA-256, HC: 1400 JtR: raw-sha256 Summary: 256-bit key and is a good partner-function for AES. Can be used in Shadow files.
Keccak-256, HC: 17800 
Haval-128, JtR: haval-128-4
Snefru-256, JtR: snefru-256

Least Likely
RIPEMD-256, JtR: dynamic_140 Haval-256 (3 rounds), JtR: dynamic_140 Haval-256 (4 rounds), JtR: dynamic_290 Haval-256 (5 rounds), JtR: dynamic_300 GOST R 34.11-94, HC: 6900 JtR: gost GOST CryptoPro
S-Box,  Blake2b-256,  SHA3-256, HC: 17400 JtR: dynamic_380 PANAMA, JtR: dynamic_320 BLAKE2-256,  BLAKE2-384,  Skein-256, JtR: skein-256 Skein-512(256),  Ventrilo,  sha256($pass.$salt), HC: 1410 
JtR: dynamic_62 sha256($salt.$pass), HC: 1420 JtR: dynamic_61 sha256(sha256($pass)), HC: 1420 JtR: dynamic_63 sha256(sha256_raw($pass))), HC: 1420 JtR: dynamic_64 sha256(sha256($pass).$salt), HC: 
1420 JtR: dynamic_65 sha256($salt.sha256($pass)), HC: 1420 JtR: dynamic_66 sha256(sha256($salt).sha256($pass)), HC: 1420 JtR: dynamic_67 sha256(sha256($pass).sha256($pass)), HC: 1420 JtR: 
dynamic_68 sha256(unicode($pass).$salt), HC: 1430  sha256($salt.unicode($pass)), HC: 1440  HMAC-SHA256 (key = $pass), HC: 1450 JtR: hmac-sha256 HMAC-SHA256 (key = $salt), HC: 1460 JtR: hmac-sha256
Cisco Type 7,  BigCrypt, JtR: bigcrypt 
                                                                                                
┌──(thm)─(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ nth -t "1DFECA0C002AE40B8619ECF94819CC1B" --no-banner

1DFECA0C002AE40B8619ECF94819CC1B

Most Likely 
MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
MD4, HC: 900 JtR: raw-md4
NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
Domain Cached Credentials, HC: 1100 JtR: mscach

Least Likely
Domain Cached Credentials 2, HC: 2100 JtR: mscach2 Double MD5, HC: 2600  Tiger-128,  Skein-256(128),  Skein-512(128),  Lotus Notes/Domino 5, HC: 8600 JtR: lotus5 md5(md5(md5($pass))), HC: 3500 
Summary: Hashcat mode is only supported in hashcat-legacy. md5(uppercase(md5($pass))), HC: 4300  md5(sha1($pass)), HC: 4400  md5(utf16($pass)), JtR: dynamic_29 md4(utf16($pass)), JtR: dynamic_33 
md5(md4($pass)), JtR: dynamic_34 Haval-128, JtR: haval-128-4 RIPEMD-128, JtR: ripemd-128 MD2, JtR: md2 Snefru-128, JtR: snefru-128 DNSSEC(NSEC3), HC: 8300  RAdmin v2.x, HC: 9900 JtR: radmin Cisco 
Type 7,  BigCrypt, JtR: bigcrypt 
                                                                                                
┌──(thm)─(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ nth -t "$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02." --no-banner

WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.

Most Likely 
BigCrypt, JtR: bigcrypt

┌──(thm)─(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ nth -t "e5d8870e5bdd26602cab8dbe07a942c8669e56d6" --no-banner

e5d8870e5bdd26602cab8dbe07a942c8669e56d6

Most Likely 
SHA-1, HC: 100 JtR: raw-sha1 Summary: Used for checksums.See more
HMAC-SHA1 (key = $salt), HC: 160 JtR: hmac-sha1
Haval-128, JtR: haval-128-4
RIPEMD-128, JtR: ripemd-128

Least Likely
Double SHA-1, HC: 4500  RIPEMD-160, HC: 6000 JtR: ripemd-160 Haval-160 (3 rounds), HC: 6000 JtR: dynamic_190 Haval-160 (4 rounds), HC: 6000 JtR: dynamic_200 Haval-160 (5 rounds), HC: 6000 JtR: 
dynamic_210 Haval-192 (3 rounds), HC: 6000 JtR: dynamic_220 Haval-192 (4 rounds), HC: 6000 JtR: dynamic_230 Haval-192 (5 rounds), HC: 6000 JtR: dynamic_240 Haval-224 (4 rounds), HC: 6000 JtR: 
dynamic_260 Haval-224 (5 rounds), HC: 6000 JtR: dynamic_270 Haval-160,  Tiger-160,  HAS-160,  LinkedIn, HC: 190 JtR: raw-sha1-linkedin Summary: Hashcat mode is only supported in oclHashcat. 
Skein-256(160),  Skein-512(160),  MangosWeb Enhanced CMS,  sha1(sha1(sha1($pass))), HC: 4600 Summary: Hashcat mode is only supported in hashcat-legacy. sha1(md5($pass)), HC: 4700  
sha1($pass.$salt), HC: 110  sha1($salt.$pass), HC: 120  sha1(unicode($pass).$salt), HC: 130  sha1($salt.unicode($pass)), HC: 140  HMAC-SHA1 (key = $pass), HC: 150 JtR: hmac-sha1 
sha1($salt.$pass.$salt), HC: 4710  MySQL5.x, HC: 300 JtR: mysql-sha1 MySQL4.1, HC: 300 JtR: mysql-sha1 Cisco Type 7,  BigCrypt, JtR: bigcrypt
```

## Level 1

#### Hash: 48bb6e862e54f2a795ffc4e541caed4d <!-- easy -->

```console
┌──(c3n0r4㉿kali)-[~/tryhackme/room]
└─$ echo -n "48bb6e862e54f2a795ffc4e541caed4d" > hash.txt 

┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt                        
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
THM{****}             (?)     
1g 0:00:00:00 DONE (2025-02-05 20:01) 50.00g/s 8620Kp/s 8620Kc/s 8620KC/s erinbear..eagames
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

#### Hash: CBFDAC6008F9CAB4083784CBD1874F76618D2A97 <!-- password123 -->

```console
┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ echo -n "CBFDAC6008F9CAB4083784CBD1874F76618D2A97" > hash.txt

┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
THM{***********}      (?)     
1g 0:00:00:00 DONE (2025-02-05 20:05) 100.0g/s 138400p/s 138400c/s 138400C/s liberty..password123
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 
```

#### Hash: 1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032 <!-- letmein -->

```console                          
┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ echo -n "1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032" > hash.txt

┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt       
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 AVX 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
THM{*******}          (?)     
1g 0:00:00:00 DONE (2025-02-05 20:07) 50.00g/s 1638Kp/s 1638Kc/s 1638KC/s 123456..eatme1
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

#### Hash: $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom <!-- bleh -->

O `Name-That-Hash` não conseguiu identificar o tipo de hash, então analisei a dica fornecida para essa questão na sala. Com base na dica, utilizei o hash `bcrypt`.

```console              
┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ grep -E '^[a-z]{4}$' /usr/share/wordlists/rockyou.txt > wordlist_4letras.txt 

┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ echo -n '$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom' > hash.txt

┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=bcrypt --wordlist=wordlist_4letras.txt hash.txt                    
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
THM{****}             (?)     
1g 0:00:00:36 DONE (2025-02-05 20:32) 0.02735g/s 13.78p/s 13.78c/s 13.78C/s alma..wawa
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

#### Hash: 279412f945939ba78ce0758d3fd83daa <!-- Eternity22 -->

```console
┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2025-02-05 20:49) 0g/s 12581Kp/s 12581Kc/s 12581KC/s  fuckyooh21..*7¡Vamos!
Session completed. 
```
O `John the Ripper` executou um ataque utilizando o formato `raw-md5`, mas não obteve sucesso. Seguindo a dica fornecida na sala, realizei um novo ataque usando o formato `raw-md4`.

```console
┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=raw-md4 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD4 [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
E********2       (?)     
1g 0:00:00:00 DONE (2025-02-05 20:59) 25.00g/s 10531Kp/s 10531Kc/s 10531KC/s evenflo..enrique69
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

# Task 2 - Level 2

#### Hash: F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85 <!-- paule -->

```console
┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ haiti F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85
SHA-256 [HC: 1400] [JtR: raw-sha256]

┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt     
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 AVX 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
THM{*****}            (?)     
1g 0:00:00:00 DONE (2025-02-05 21:01) 33.33g/s 3276Kp/s 3276Kc/s 3276KC/s ryanscott..Donovan
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed. 
```

#### Hash: 1DFECA0C002AE40B8619ECF94819CC1B <!-- n63umy8lkf4i -->

```console
┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ echo -n '1DFECA0C002AE40B8619ECF94819CC1B' > hash.txt

┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
THM{************}     (?)     
1g 0:00:00:00 DONE (2025-02-05 21:07) 1.851g/s 9701Kp/s 9701Kc/s 9701KC/s n6546442..n626891
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
```

#### Hash: $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02. <br> Salt: aReallyHardSalt <!-- waka99 -->

```console
┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ echo -n '$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02' > hash.txt

┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=bigcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt                                                  
Error: No format matched requested name 'bigcrypt'
```

> Durante a pesquisa sobre o suporte ao formato `bigcrypt` no `John the Ripper`, descobri que:
- O `bigcrypt` é um formato antigo, originalmente criado para hashes DES baseados em arquivos grandes.
- Atualmente, esse formato não está presente na versão moderna do `John the Ripper Jumbo`, pois foi removido, renomeado ou incorporado a outro formato.
- Além disso, a maioria dos sistemas hoje utiliza algoritmos mais modernos, como `bcrypt` e `sha512crypt`.
{: .prompt-info }

Portanto, seguindo a lógica do hash `$6$aReallyHardSalt$...`, apresentado na `Tarefa 1`, pesquisei sobre hashes iniciados por `$6$` e identifiquei que se trata do formato `SHA512-Crypt`.

```console
┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ echo -n '$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.' > hash.txt

┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt                                                
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Note: Passwords longer than 26 [worst case UTF-8] to 79 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
THM{******}           (?)     
1g 0:00:46:37 DONE (2025-02-05 21:45) 0.000357g/s 1012p/s 1012c/s 1012C/s wakablonde..waiyavi
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

#### Hash: e5d8870e5bdd26602cab8dbe07a942c8669e56d6 <br> Salt: tryhackme <!-- 481616481616 -->

```console
┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ echo -n 'e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme' > hash.txt

┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
No password hashes loaded (see FAQ)

┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ john --format=hmac-sha1 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
No password hashes loaded (see FAQ)
```
> O formato `hmac-sha1` do john utiliza a senha como chave (salt) e a string original como mensagem, ou seja, a ordem é invertida em relação ao hashcat no `modo -m 160`:
- `John`: hmac-sha1(password, salt)
- `Hashcat`: hmac-sha1(salt, password)
{: .prompt-info }

Tentei inverter a ordem na geração do arquivo de hash para john, mas sem sucesso. Portanto, a última questão foi resolvida utilizando o hashcat.

```console
┌──(c3n0r4㉿kali)-[~/tryhackme/room/crackthehash]
└─$ hashcat -m 160 -a 0 hash.txt /usr/share/wordlists/rockyou.txt        
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-ivybridge-Intel(R) Core(TM) i5-3337U CPU @ 1.80GHz, 2146/4357 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme:THM{************}
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 160 (HMAC-SHA1 (key = $salt))
Hash.Target......: e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme
Time.Started.....: Wed Feb 05 21:52:16 2025 (8 secs)
Time.Estimated...: Wed Feb 05 21:52:24 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1497.4 kH/s (0.86ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 12314624/14344385 (85.85%)
Rejected.........: 0/12314624 (0.00%)
Restore.Point....: 12312576/14344385 (85.84%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 48162450 -> 481101133
Hardware.Mon.#1..: Temp: 72c Util: 74%

Started: Wed Feb 05 21:51:51 2025
Stopped: Wed Feb 05 21:52:25 2025
```

Uma alternativa muito mais ágil para resolver esta sala é a plataforma [hashes.com](https://hashes.com/en/decrypt/hash), que utiliza o conceito de `rainbow tables`.

> As tabelas rainbow são grandes bancos de dados pré-computados que armazenam correspondências entre `hashes` e seus respectivos `valores em texto simples`. Ao invés de realizar o processo de quebra de senha em tempo real, essas tabelas permitem a consulta direta para descobrir o valor original de um hash conhecido.
Essa abordagem é extremamente eficaz para hashes `sem salt` ou com `salts comuns`, acelerando significativamente o processo de quebra.
{: .prompt-info }

Abaixo estão as respostas de todas as questões obtidas utilizando esse conceito o processo levou menos de um minuto.
![hashes.com](hashes.webp)
