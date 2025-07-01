---
title: "Projeto: Network Operations Center (NOC)"
date: 2025-06-26 16:30:00 -0300
categories: [Basico]
tags: [Teorica]
description: "Profissional em início de carreira, responsável por monitoramento básico, identificação preliminar de ameaças e suporte às operações de segurança. Atua seguindo procedimentos estabelecidos e orientações de profissionais mais experientes, desenvolvendo habilidades técnicas e conhecimento do ambiente de segurança."
image:
  path: /assets/img/PROJredes.png
  alt: Ilustração de um computador moderno com elementos de código e processamento
---

# O que é NOC?

**NOC** (Network Operations Center), ou Centro de Operações de Rede, é uma unidade especializada responsável pelo monitoramento, gerenciamento e manutenção da infraestrutura de rede e sistemas de uma organização.

## Objetivo do NOC

O principal objetivo do NOC é garantir que a rede, servidores, aplicações e demais componentes de TI estejam operando de forma estável, segura e eficiente, minimizando o tempo de indisponibilidade e prevenindo falhas que possam afetar o negócio.

## Funções principais do NOC

- **Monitoramento contínuo:** acompanha o desempenho e a disponibilidade dos equipamentos e serviços de rede 24/7.  
- **Detecção e resposta a incidentes:** identifica rapidamente problemas, realiza diagnósticos iniciais e aciona equipes de suporte para resolução.  
- **Gerenciamento de mudanças:** controla atualizações, patches e configurações para manter a rede segura e atualizada.  
- **Documentação e relatórios:** mantém registros detalhados dos eventos, incidentes e ações tomadas, auxiliando em análises e auditorias.  
- **Coordenação com outras equipes:** atua em conjunto com times de segurança (Blue Team), suporte técnico e engenharia para garantir a integridade do ambiente.

## Importância do NOC

Um NOC eficiente é vital para assegurar a continuidade dos serviços de TI, reduzindo riscos operacionais e garantindo que a organização possa responder rapidamente a ameaças e falhas técnicas.

---


# 🔵 Fundamentos de Redes

Para atuar de forma eficaz na defesa cibernética, um profissional Blue Team precisa compreender os **fundamentos das redes**. Esses conhecimentos são essenciais para analisar tráfego, detectar comportamentos anômalos e identificar ameaças que se propagam pela rede.

A base de toda defesa é entender como o tráfego legítimo se comporta.

# 🧱 Modelo OSI – A Estrutura da Comunicação

Para entender como os dados trafegam em uma rede, é essencial conhecer o **modelo OSI (Open Systems Interconnection)**.  
Ele divide a comunicação em **7 camadas**, cada uma com responsabilidades específicas. Isso facilita a análise, o diagnóstico de problemas e a identificação de comportamentos maliciosos.

Esse modelo é uma **base essencial para profissionais Blue Team**, pois permite compreender onde ocorrem ataques, falhas e desvios no tráfego.

---

## 🧩 As 7 Camadas do Modelo OSI

Cada camada desempenha uma função no envio e recebimento de dados.  
Da **Camada 1 (Física)** até a **Camada 7 (Aplicação)**, os dados são processados, empacotados, transmitidos e interpretados.

| Camada | Nome                      | Função Principal                                |
|--------|---------------------------|--------------------------------------------------|
| 7      | Aplicação                 | Interação com o usuário (HTTP, DNS, FTP)         |
| 6      | Apresentação              | Criptografia, compressão (TLS, JPEG)             |
| 5      | Sessão                    | Controle de sessões (RPC, NetBIOS)               |
| 4      | Transporte                | Controle de fluxo (TCP, UDP)                     |
| 3      | Rede                      | Roteamento e endereçamento (IP)                  |
| 2      | Enlace de Dados           | MAC, switches, detecção de erros                 |
| 1      | Física                    | Cabos, sinais, hubs                              |

---

## 🧠 Como Pensar em Cada Camada

```
🟣 **Camada 7 – Aplicação**  
A interface entre o usuário e a rede. Ex: navegadores, clientes de e-mail.

🔵 **Camada 6 – Apresentação**  
Formata os dados. Pode criptografar (TLS) ou compactar (JPEG).

🟢 **Camada 5 – Sessão**  
Gerencia sessões entre aplicações. Ex: login contínuo em serviços.

🟡 **Camada 4 – Transporte**  
Responsável pela entrega confiável (TCP) ou rápida (UDP).

🟠 **Camada 3 – Rede**  
Decide o caminho que os pacotes irão percorrer (roteamento via IP).

🔴 **Camada 2 – Enlace**  
Identifica dispositivos com endereços MAC e garante entrega local.

⚫ **Camada 1 – Física**  
Transmite bits através de cabos, rádio ou fibra.
```

---

## 📡 Modelo OSI na Prática

O modelo OSI é uma **abstração**, mas tem grande valor prático. Ele permite que analistas:

- Diagnostiquem falhas (em que camada está o problema?)  
- Localizem ataques (ex: um DDoS na camada 4 ou 7)  
- Compreendam como ferramentas operam (Wireshark, IDS, firewalls)

---

## 🛡️ Relevância para o Blue Team

Para o analista de defesa, entender o modelo OSI é essencial para:

- Interpretar capturas de pacotes e logs  
- Detectar anomalias de tráfego em diferentes camadas  
- Criar regras de alerta com base em protocolos e comportamentos  
- Identificar ataques em camadas específicas (ex: SQLi → camada 7, ICMP → camada 3)

Dominar o modelo OSI permite enxergar a rede de forma **estruturada e estratégica**.



# 🌐 Endereçamento IP (IPv4)

O **endereço IP (Internet Protocol)** é o identificador único de um dispositivo em uma rede.  
Ele é fundamental para o **roteamento, comunicação e identificação de ativos**, sendo um conceito crucial para profissionais de cibersegurança.

O IPv4 é a versão mais utilizada e apresenta endereços no formato **decimal com 4 octetos**, como `192.168.0.10`.

---

## 🔢 Estrutura de um IP

Um endereço IPv4 possui **32 bits**, divididos em 4 blocos de 8 bits (octetos).

Exemplo:

```
IP: 192.168.0.10  
Binário: 11000000.10101000.00000000.00001010
```

A máscara de sub-rede (ex: `255.255.255.0`) determina **quantos bits pertencem à rede** e **quantos ao host**.

---

## 🧱 Classes de IP

O IPv4 foi originalmente dividido em **classes**, embora hoje se use mais o conceito de sub-redes com CIDR (`/24`, `/16`, etc.).

| Classe | Intervalo Inicial     | Uso Comum                         |
|--------|------------------------|-----------------------------------|
| A      | 1.0.0.0 – 126.255.255.255 | Grandes redes                     |
| B      | 128.0.0.0 – 191.255.255.255 | Redes médias                      |
| C      | 192.0.0.0 – 223.255.255.255 | Pequenas redes                    |

---

## 🏠 IPs Públicos e Privados

| Tipo   | Descrição                                      | Exemplos                      |
|--------|------------------------------------------------|-------------------------------|
| 🔒 **Privado** | Usado dentro de redes internas               | `192.168.x.x`, `10.x.x.x`     |
| 🌍 **Público** | Usado para comunicação externa (Internet) | Atribuído por ISPs            |

IPs privados **não são roteáveis pela internet**, e são usados em redes locais com NAT.

---

## 📏 Máscara de Sub-rede

A **máscara** define o tamanho da rede e quantos IPs ela pode conter.

Exemplos:

| Máscara           | CIDR  | IPs possíveis (hosts) |
|-------------------|-------|------------------------|
| 255.255.255.0     | /24   | 254                    |
| 255.255.0.0       | /16   | 65.534                 |
| 255.0.0.0         | /8    | 16.777.214             |

---

## 🧠 CIDR – Notação Simplificada

O **CIDR (Classless Inter-Domain Routing)** define a sub-rede com a notação `/n`, onde `n` é o número de bits da rede.

```
Exemplo:  
192.168.1.0/24  
➡️ 24 bits para a rede  
➡️ 8 bits para hosts (2⁸ - 2 = 254 IPs utilizáveis)
```

---

## 🛡️ Relevância para o Blue Team

Compreender o endereçamento IP permite:

- Identificar **ativos críticos e suas redes**  
- Detectar tráfego **anômalo fora do escopo esperado**  
- Criar regras em **firewalls, SIEMs e IDS** com base em IPs ou sub-redes  
- Correlacionar eventos por origem/destino IP  
- Monitorar e isolar **sub-redes comprometidas**

Dominar IPv4 é o primeiro passo para entender a movimentação dos dados na rede.



# 🌐 Protocolo DNS – O Tradutor da Internet

O **DNS (Domain Name System)** é um dos pilares da internet. Ele atua como um "tradutor", convertendo **nomes de domínio** (como `google.com`) em **endereços IP** (como `142.250.190.78`), permitindo que os usuários acessem sites de forma amigável.

Para o Blue Team, o DNS é uma **fonte valiosa de informações** — tanto para detecção de ameaças quanto para investigação de ataques em andamento.

---

## 🧠 Como o DNS Funciona?

Quando você acessa um site, o DNS segue uma **cadeia de resolução** até encontrar o IP correspondente ao nome:

1. Verifica o **cache local**  
2. Consulta o **servidor DNS recursivo**  
3. Passa por **servidores raiz**, **TLDs** (`.com`, `.org`, etc.)  
4. Chega ao **servidor autoritativo**, que responde com o IP

```
Exemplo:  
Você digita `chat.openai.com` → o DNS retorna `104.18.12.123`  
```

---

## 📄 Tipos de Registros DNS

| Tipo   | Nome                 | Finalidade                                  |
|--------|----------------------|----------------------------------------------|
| A      | Address              | IP IPv4 do domínio                           |
| AAAA   | IPv6 Address         | IP IPv6 do domínio                           |
| MX     | Mail Exchange        | Servidor de e-mail do domínio                |
| TXT    | Text                 | Informações adicionais (SPF, DKIM, verificação) |
| CNAME  | Canonical Name       | Apelido de outro domínio                     |
| NS     | Name Server          | Indica os servidores autoritativos           |
| PTR    | Pointer              | Usado em **resolução reversa**               |

---

## 🔄 Resolução Direta vs. Reversa

- **Resolução direta:** nome de domínio → IP  
- **Resolução reversa:** IP → nome de domínio (via registro **PTR**)  

Muito usada em auditorias, correlação de logs e análises forenses.

---

## 🚨 Ataques Comuns via DNS

| Ataque            | Descrição                                                           |
|-------------------|----------------------------------------------------------------------|
| DNS Spoofing      | Resposta falsa com IP malicioso                                      |
| DNS Tunneling     | Comunicação encoberta via requisições DNS                           |
| DNS Amplification | DDoS usando servidores DNS para refletir tráfego contra a vítima     |

---

## 🛠 Ferramentas de Análise

- `nslookup` – consulta simples a registros  
- `dig` – ferramenta avançada de diagnóstico  
- **SIEMs** – correlacionam padrões de requisição DNS suspeitos  
- **Wireshark** – permite inspecionar pacotes DNS em profundidade  

---

## 🛡️ Relevância para o Blue Team

Monitorar e analisar DNS permite ao analista:

- Detectar **comunicação C2 encoberta via DNS tunneling**  
- Identificar **resoluções suspeitas ou inesperadas**  
- Bloquear domínios maliciosos em **firewalls e proxies**  
- Correlacionar nomes de domínio com **IPs de origem/destino**  
- Investigar campanhas de **phishing** baseadas em domínios falsos

O DNS é uma **mina de ouro para a defesa cibernética** — quando bem monitorado.



# 🌐 Protocolo HTTP/HTTPS – A Base da Web

O **HTTP (Hypertext Transfer Protocol)** é o protocolo usado para **comunicação na web**. Ele permite que navegadores e servidores troquem informações — como páginas HTML, arquivos, imagens e APIs.

O **HTTPS** é a versão **segura** do HTTP, que utiliza **TLS (Transport Layer Security)** para proteger os dados durante a transmissão.

Para o Blue Team, compreender o funcionamento do HTTP/HTTPS é essencial para **monitorar tráfego web**, detectar **ataques via navegador** e proteger aplicações web.

---

## 🧱 Estrutura de uma Requisição HTTP

Uma comunicação HTTP básica segue este padrão:

```
Cliente (navegador) envia:

GET /index.html HTTP/1.1  
Host: www.exemplo.com  
User-Agent: Mozilla/5.0  
Cookie: id=1234  

Servidor responde:

HTTP/1.1 200 OK  
Content-Type: text/html  
Set-Cookie: id=1234  
```

---

## 🔧 Métodos HTTP Comuns

| Método  | Finalidade                               |
|---------|-------------------------------------------|
| GET     | Solicita dados (sem corpo)                |
| POST    | Envia dados no corpo da requisição        |
| PUT     | Atualiza um recurso existente             |
| DELETE  | Remove um recurso                         |
| PATCH   | Atualiza parcialmente um recurso          |
| OPTIONS | Descobre métodos permitidos no endpoint   |

---

## 🔁 Códigos de Resposta

| Código | Significado               |
|--------|---------------------------|
| 200    | OK – Requisição bem-sucedida       |
| 301    | Redirecionamento permanente         |
| 403    | Proibido – sem permissão            |
| 404    | Não encontrado                      |
| 500    | Erro interno do servidor            |

---

## 📎 Cabeçalhos Importantes

Cabeçalhos HTTP são usados para transmitir metadados nas requisições e respostas.

| Cabeçalho      | Função                                         |
|----------------|------------------------------------------------|
| Host           | Indica o domínio do destino                    |
| User-Agent     | Identifica o cliente (navegador, app, etc.)    |
| Cookie         | Armazena dados de sessão ou rastreamento       |
| Referer        | Informa a origem da requisição                 |
| Content-Type   | Define o tipo de dado enviado (JSON, HTML...)  |

---

## 🔐 HTTPS – Segurança com TLS

O **HTTPS** protege os dados com **criptografia TLS**, garantindo:

- Confidencialidade: ninguém pode ler o tráfego  
- Integridade: os dados não são alterados no caminho  
- Autenticidade: garante que o servidor é legítimo (via certificado)

```
Exemplo de URL segura:  
https://meusite.com  
➡️ Cadeado no navegador  
➡️ Tráfego criptografado com TLS  
```

---

## 🚨 Ameaças Relacionadas

- **Injeção (SQLi, XSS):** via parâmetros HTTP maliciosos  
- **Session hijacking:** roubo de cookies de sessão  
- **Phishing:** sites falsos com páginas HTTP/HTTPS  
- **Exfiltração de dados:** via POST encoberto ou C2 web

---

## 🛡️ Relevância para o Blue Team

Entender HTTP/HTTPS permite ao analista:

- Monitorar **requisições suspeitas** em aplicações web  
- Identificar **tentativas de exploração via payloads HTTP**  
- Criar **regras no SIEM** com base em cabeçalhos ou métodos  
- Analisar **logs de web servers** (Apache, Nginx, IIS)  
- Detectar **comunicação com domínios maliciosos em HTTPS**

HTTP/HTTPS é onde muito do tráfego legítimo e malicioso passa — por isso, é um dos focos críticos da defesa.



# 🔁 Protocolos TCP e UDP – Transporte de Dados na Rede

Os protocolos **TCP** e **UDP** pertencem à **Camada 4 (Transporte)** do modelo OSI.  
Eles são responsáveis por **entregar dados entre dispositivos** — como sites, aplicativos, servidores e dispositivos IoT.

Embora ambos tenham o mesmo propósito geral (transporte), eles funcionam de maneiras **muito diferentes**, o que impacta diretamente na **análise de tráfego e resposta a incidentes**.

---

## 🧩 TCP – Transmission Control Protocol

O **TCP** é um protocolo **confiável e orientado à conexão**. Ele garante que os dados cheguem completos e na ordem correta.

### 🛠 Características:

- Garante entrega com **confirmação de recebimento (ACK)**  
- Utiliza **controle de fluxo** e **retransmissão** em caso de perda  
- Realiza o **three-way handshake** antes de transmitir dados

```
Etapas do Three-Way Handshake:

1️⃣ Cliente envia `SYN`  
2️⃣ Servidor responde com `SYN-ACK`  
3️⃣ Cliente responde com `ACK`  
➡️ Conexão estabelecida  
```

### 📦 Aplicações que usam TCP:

- HTTP / HTTPS  
- SSH  
- FTP  
- SMTP (e-mail)

---

## 🧩 UDP – User Datagram Protocol

O **UDP** é um protocolo **não confiável e sem conexão**.  
Ele **não garante entrega**, mas é **mais rápido e leve**.

### 🛠 Características:

- Sem handshake nem confirmação  
- Sem retransmissões ou ordenação  
- Ideal para aplicações que toleram perdas e exigem baixa latência

```
Exemplo:  
Enviar 100 pacotes UDP → o receptor pode receber 95, sem erro.  
➡️ Não há aviso sobre perdas.
```

### 📦 Aplicações que usam UDP:

- DNS  
- DHCP  
- VoIP  
- Streaming de vídeo/áudio  
- Jogos online

---

## ⚖️ Comparativo TCP vs UDP

| Protocolo | Confiabilidade | Ordem dos dados | Velocidade | Uso comum                      |
|-----------|----------------|------------------|------------|-------------------------------|
| TCP       | ✅ Sim         | ✅ Garante       | 🐢 Mais lento | Web, e-mail, SSH              |
| UDP       | ❌ Não         | ❌ Não garante   | ⚡ Mais rápido | Streaming, DNS, VoIP, jogos   |

---

## 🧠 Como o Blue Team Usa Isso

Saber **diferenciar TCP de UDP** é fundamental para análise de tráfego:

- Ataques como **SYN flood** afetam **TCP**  
- Exfiltração via **DNS tunneling** ocorre por **UDP**  
- Protocolos de C2 (comando e controle) podem usar **ambos**, dependendo da evasão  
- Firewalls e IDS aplicam **regras distintas para TCP e UDP**

---

## 🛡️ Relevância para o Blue Team

Dominar os protocolos de transporte permite ao analista:

- Criar **regras mais precisas** em firewalls, SIEMs e IDS  
- Identificar **comunicação maliciosa por portas incomuns**  
- Distinguir tráfego legítimo de **análise de portas (port scan)**  
- Monitorar **padrões de tráfego suspeitos** (ex: uso incomum de UDP)  
- Diagnosticar **problemas de entrega ou conectividade**

TCP e UDP são a **base da comunicação digital moderna** — e do tráfego que o Blue Team precisa vigiar de perto.

# 📶 ICMP – O Protocolo da Comunicação de Erros

O **ICMP (Internet Control Message Protocol)** é um protocolo fundamental para a **comunicação e diagnóstico de redes**. Embora não transporte dados de aplicações, ele é essencial para identificar falhas, testar conexões e gerar alertas sobre problemas na entrega de pacotes.

Profissionais do **Blue Team** utilizam o ICMP para monitorar a saúde da rede e detectar possíveis tentativas de varredura ou movimentação lateral.

## 🔍 O que é ICMP?

O ICMP faz parte do **protocolo IP**, operando na **Camada 3 (Rede)** do modelo OSI. Ele é usado para:

- Enviar mensagens de **erro e controle**
- Indicar se um host está **disponível ou não**
- Sinalizar problemas como **rota inacessível**, **TTL excedido**, etc.

**Importante:** ICMP **não usa portas**, diferente de TCP e UDP.

## 📡 Tipos de Mensagens ICMP

As mensagens ICMP são classificadas por **Tipo** e **Código**, e cada uma representa uma função diferente.

| Tipo | Nome                      | Função                                                    |
|------|---------------------------|------------------------------------------------------------|
| 0    | Echo Reply                | Resposta a um ping                                         |
| 3    | Destination Unreachable   | Destino inacessível                                        |
| 5    | Redirect Message          | Redirecionamento de rota                                   |
| 8    | Echo Request              | Requisição de ping                                         |
| 11   | Time Exceeded             | TTL excedido no caminho                                    |
| 13/14| Timestamp Request/Reply   | Sincronização de horário                                   |

## 🧪 Ferramentas que usam ICMP

O ICMP está presente em ferramentas de diagnóstico de rede como:

- `ping` – Testa a conectividade com outro host  
- `traceroute` – Mapeia o caminho até um destino (usando ICMP ou UDP)  
- `hping` – Permite manipular pacotes ICMP para testes mais avançados  

## 🚨 ICMP e Segurança

Apesar de legítimo, o ICMP pode ser explorado por atacantes:

- **Ping Sweep:** escaneamento de hosts ativos  
- **ICMP Tunneling:** tunelamento de dados para evasão de firewall  
- **Flooding (DoS):** sobrecarga com mensagens ICMP (ex: Smurf Attack)

Por isso, é comum filtrar ou limitar ICMP em **firewalls e roteadores**.

## 🛡️ Relevância para o Blue Team

Dominar o ICMP ajuda o analista Blue Team a:

- Monitorar **disponibilidade de sistemas e redes**  
- Detectar **varreduras e movimentações maliciosas**  
- Criar **regras de alerta no SIEM** para mensagens ICMP suspeitas  
- Investigar falhas de **conectividade e roteamento**  
- Responder a incidentes relacionados a **DoS ou tunneling**


# 🤝 TCP Handshake – Como a Conexão é Estabelecida

O **TCP (Transmission Control Protocol)** é um protocolo confiável de transporte que garante a entrega de dados entre dois pontos.  
Antes de qualquer comunicação, o TCP realiza um processo chamado **three-way handshake**, responsável por **estabelecer uma conexão estável**.

Profissionais Blue Team precisam entender esse processo para identificar comportamentos legítimos e detectar **atividades suspeitas**, como **port scanning**, **spoofing** ou **tentativas de negação de serviço**.

## 🔄 O que é o Three-Way Handshake?

O **three-way handshake** é o processo de três etapas usado para **iniciar uma conexão TCP** entre cliente e servidor.

Ele serve para:

- Sincronizar os números de sequência (SEQ)  
- Estabelecer parâmetros da sessão  
- Confirmar que ambos os lados estão prontos para se comunicar

---

### 🧭 Etapas do Handshake

| Etapa | Origem     | Descrição                                                                 |
|-------|------------|---------------------------------------------------------------------------|
| 1     | Cliente → Servidor | Envia um **SYN** com seu número de sequência inicial (ex: SEQ = 1000)       |
| 2     | Servidor → Cliente | Responde com **SYN-ACK** (ex: SEQ = 2000, ACK = 1001)                    |
| 3     | Cliente → Servidor | Envia um **ACK** final (ACK = 2001), concluindo a conexão                  |

Após isso, a sessão está aberta e os dados podem começar a ser trocados.

---

### 📥 Exemplo Visual

```
Cliente               Servidor
   | ---- SYN ------> |
   | <--- SYN-ACK --- |
   | ---- ACK ------> |
```

---

## 🛠️ Análise no Wireshark

Durante uma captura de tráfego, o three-way handshake pode ser identificado por:

- `Flags [S]` – Pacote SYN  
- `Flags [S, ACK]` – Resposta do servidor  
- `Flags [ACK]` – Confirmação do cliente  

Verificar os **números de sequência** e **tempo entre pacotes** pode revelar anomalias, como tentativas de **SYN flood** ou **spoofing**.

---

## 🧨 Ameaças Relacionadas

- **SYN Flood (DoS):** o atacante envia muitos SYNs sem completar o handshake  
- **Port Scanning:** ferramentas como `nmap` usam SYN para descobrir portas abertas  
- **Spoofing:** falsificação de IPs com pacotes SYN para burlar regras de firewall  

---

## 🛡️ Relevância para o Blue Team

Compreender o handshake TCP permite ao analista:

- Detectar **tentativas de conexão maliciosas**  
- Criar regras no SIEM para **analisar conexões incompletas**  
- Responder a **ataques baseados em SYN flood**  
- Identificar **scans furtivos ou comunicação anômala**

A observação do handshake é **fundamental em qualquer análise de tráfego de rede**.

# Ferramentas de NOC (Network Operations Center)

No ambiente de um NOC, o uso de ferramentas eficientes é fundamental para o monitoramento, gerenciamento e manutenção da infraestrutura de rede e sistemas. A seguir, uma análise das principais ferramentas usadas em NOCs: **Zabbix, Grafana, PHPIPAM e GLPI**.

---

## 🛠️ Zabbix

O **Zabbix** é uma plataforma open-source para **monitoramento de redes, servidores, aplicações e serviços**.

### Características principais:

- Monitoramento em tempo real de disponibilidade e desempenho  
- Coleta de métricas via agentes ou protocolos SNMP, IPMI, JMX, etc.  
- Sistema flexível de alertas e notificações configuráveis  
- Dashboards e relatórios personalizáveis  
- Suporte para monitoramento distribuído e alta disponibilidade

### Uso no NOC:

Zabbix é usado para detectar falhas e degradação na rede ou nos servidores, permitindo respostas rápidas e prevenção de downtime.

---

## 📊 Grafana

O **Grafana** é uma plataforma de análise e visualização de métricas em tempo real, que se integra a diversas fontes de dados.

### Características principais:

- Dashboards interativos e altamente customizáveis  
- Suporte a várias fontes de dados: Prometheus, InfluxDB, Elasticsearch, Zabbix, entre outros  
- Alertas configuráveis baseados em regras definidas  
- Plugins para gráficos, mapas de calor, tabelas e muito mais

### Uso no NOC:

Grafana é amplamente utilizado para criar painéis visuais que facilitam a compreensão do estado da infraestrutura, complementando ferramentas de monitoramento como o Zabbix.

---

## 🌐 PHPIPAM

O **PHPIPAM** é uma aplicação web open-source para **gerenciamento de endereçamento IP (IPAM)**.

### Características principais:

- Inventário e organização de blocos IP, sub-redes e endereços IP individuais  
- Suporte a VLANs, VRFs e hierarquias complexas de redes  
- Documentação de dispositivos e comentários  
- Controle de acesso baseado em permissões  
- API para integração com outras ferramentas

### Uso no NOC:

PHPIPAM ajuda o NOC a manter um controle preciso sobre os recursos de endereçamento IP, evitando conflitos e facilitando o planejamento e troubleshooting.

---

## 🖥️ GLPI

O **GLPI (Gestionnaire Libre de Parc Informatique)** é um sistema de gerenciamento de recursos de TI e **central de serviços (ITSM)**.

### Características principais:

- Inventário automático e manual de hardware e software  
- Gestão de chamados (tickets) e fluxo de trabalho  
- Base de conhecimento para suporte  
- Controle de contratos, fornecedores e custos  
- Relatórios e dashboards para análise de desempenho

### Uso no NOC:

GLPI organiza e centraliza o suporte técnico, facilitando a gestão dos incidentes, solicitações e ativos, otimizando o trabalho do time de operações.

---

## Resumo

| Ferramenta | Função Principal                      | Uso no NOC                                   |
|------------|-------------------------------------|----------------------------------------------|
| Zabbix     | Monitoramento de rede e sistemas    | Detectar falhas e performance em tempo real  |
| Grafana    | Visualização de métricas e dashboards| Painéis interativos para análise visual       |
| PHPIPAM    | Gerenciamento de endereçamento IP   | Controle e planejamento de IPs e sub-redes   |
| GLPI       | Gestão de ativos e suporte técnico   | Administração de chamados, inventário e suporte |

---

Essas ferramentas, usadas em conjunto, permitem que o NOC mantenha a infraestrutura da rede saudável, otimizada e com alta disponibilidade, além de garantir agilidade no atendimento a incidentes.

