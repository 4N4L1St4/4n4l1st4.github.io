---
title: "Rotina Time Cyber"
date: 2025-06-26 16:30:00 -0300
categories: [Purple Team, Rotina]
tags: [Prática, Cybersecurity, Blue Team, SOC]
description: "Uma jornada prática sobre o que um analista de cibersegurança precisa saber e executar no dia a dia para proteger ambientes corporativos."
image:
  path: /assets/img/PROJsiem.png
  alt: Ilustração de um ambiente de monitoramento de segurança com SIEM e análise de eventos
---

# Coloque em prática o que você encontrará aqui — vamos construir juntos um ciberespaço mais seguro.

A segurança não nasce pronta. Ela evolui.

Assim como todo profissional de TI começa no laboratório, testando, errando e aprendendo, as empresas também iniciam suas operações de forma simples — com poucos recursos, processos básicos e muitas vezes sem uma estrutura formal de proteção.

Com o crescimento do negócio surgem novos sistemas, novos usuários, integrações, acessos remotos, dados sensíveis e responsabilidades legais. E junto com essa expansão vêm os **riscos**, os **processos legados** e as **vulnerabilidades acumuladas ao longo do tempo**.

É nesse momento que a segurança precisa acompanhar a maturidade da empresa. Esta série foi criada para mostrar exatamente essa jornada:

* ➡ Da infraestrutura improvisada para o ambiente controlado 
* ➡ Da ausência de visibilidade para o monitoramento contínuo 
* ➡ Da reação ao incidente para a defesa estratégica 

Aqui você não verá apenas teoria — verá a **evolução real de um Time Cyber**, acompanhando o crescimento do negócio e a necessidade de novos processos, novas tecnologias e novas especializações.

Porque segurança não é um projeto com início e fim. É um processo contínuo de maturidade.

---

## 🎯 Objetivo do dia 1: O que é começar na área de cibersegurança.
**Resumo:**  
Começar na área de cibersegurança é ter contato com **tecnologia, processos e pessoas**. Essas três engrenagens trabalham juntas para fazer uma empresa funcionar. Logo, se você tem um papel dentro de qualquer uma dessas áreas, já pode contribuir com segurança da informação. O setor de Cyber é baseado nos três pilares do **CID**: **confidencialidade, integridade e disponibilidade**. Apesar de ser um conceito inicial e mais genérico, ele serve como base para aprofundamentos conforme você ganha experiência dentro da organização.

**Como:**  
Se você já atua em TI, como help desk, já pode começar na segurança da informação. Um ponto essencial — e que facilita muito o trabalho do time de Cyber — é manter um **inventário de dispositivos completo e atualizado**, pois decisões importantes dependem de informações como quantidade de equipamentos, sistemas operacionais e versões, além de programas instalados. Isso impacta diretamente ações como a compra de licenças de antivírus (AV), considerando o número real de máquinas (workstations e servidores), seus sistemas (Windows ou Linux) e compatibilidade dos agentes de segurança. Também é importante avaliar ambientes com sistemas legados, como Windows 7, Windows 10 em fim de vida e versões antigas de Windows Server, priorizando versões mais recentes. Além disso, incluir smartphones, tablets e ativos de rede no inventário melhora a visibilidade do ambiente. Para quem é de desenvolvimento, é fundamental mapear bibliotecas utilizadas, suas versões e possíveis vulnerabilidades (CVE). Já para quem não é de TI, entender o funcionamento de e-mails, servidores de arquivos e impressão já é um ótimo começo, principalmente porque podem envolver dados sensíveis. Entrar em cibersegurança é fácil; o desafio é se manter atualizado — estudar constantemente é parte do processo.

## 🎯 Objetivo do dia 2: Entenda que toda empresa deve ter um firewall com IDS e IPS, no mínimo
**Resumo:**  
Um firewall centralizando o tráfego pode ser tanto um ponto positivo quanto negativo. O lado negativo é a necessidade de um equipamento robusto para suportar a inspeção de todo o tráfego que passa por ele. Por outro lado, os benefícios são significativos: a detecção com IDS e a resposta ativa com IPS (como drop, accept e reject) são um ótimo ponto de partida para proteção do ambiente, tanto no tráfego de entrada quanto de saída. Além disso, controles básicos como IP de origem, IP de destino e porta de destino são fundamentais para estabelecer uma primeira camada de segurança.

**Como:**  
A implementação de um firewall varia conforme o porte da empresa, seja pequena, média ou grande, mas a partir de ambientes de médio porte já existe uma maturidade maior sobre a necessidade desse tipo de solução para disponibilizar serviços com segurança, tanto interna quanto externamente. Existem diversas opções no mercado, desde soluções open source como pfSense até fabricantes consolidados como Check Point, FortiGate, Sophos e SonicWall. Cada um possui custos e níveis de inteligência diferentes, especialmente na atuação do IPS, mas todos oferecem o básico necessário: controle de acesso por origem, destino e porta, além de mecanismos de detecção e resposta. O ponto principal é entender que toda empresa precisa ter um firewall protegendo o tráfego de entrada e saída do seu ambiente.


## 🎯 Objetivo do dia 3: Entenda que toda empresa deve ter, no mínimo, um AV — e, idealmente, um EDR
**Resumo:**  
Para manter o ambiente seguro, principalmente considerando o elo mais fraco — as pessoas — é essencial ter controle sobre os endpoints (workstations dos colaboradores) e também sobre os servidores. Com o uso de um antivírus (AV), você obtém proteção baseada em assinaturas conhecidas. Por exemplo, ataques como o WannaCry hoje têm menor probabilidade de sucesso, pois seus endereços IP e hashes de arquivos já são conhecidos. No entanto, esse modelo pode falhar, já que pequenas alterações, como mudança de IP ou modificação no arquivo, podem burlar a detecção. Por isso, o EDR surge como uma evolução, utilizando análise comportamental para identificar ameaças mais sofisticadas. Exemplos de soluções incluem Harmony, SentinelOne, CrowdStrike e Kaspersky.

**Como:**  
Você precisa levar para a sua organização a visibilidade dessa necessidade, começando pelo básico: a implementação de um antivírus corporativo. Não é recomendado confiar apenas no Microsoft Defender, nem ignorar riscos como escalada de privilégios em ambientes Linux. É importante conscientizar os gestores sobre a importância dessa camada de proteção e, caso exista orçamento disponível, evoluir para uma solução de EDR. Normalmente, essas ferramentas são licenciadas por ativo (dispositivo instalado), com custo médio por endpoint, o que facilita o planejamento de investimento conforme o tamanho do ambiente.

## 🎯 Objetivo do dia 4: Entenda que toda empresa deve ter uma solução de antimail
**Resumo:**  
O método mais comum de invasão e coleta de informações continua sendo o phishing — isso não é segredo. Por isso, é fundamental entender que um serviço de antimail ajuda a automatizar a detecção de e-mails fraudulentos, reduzindo significativamente o risco de comprometimento da empresa. Essa camada de segurança atua diretamente na principal porta de entrada de ataques, protegendo usuários contra ameaças que chegam por e-mail.

**Como:**  
Existem diversas soluções de antispam/antimail no mercado, como o FortiMail. A tecnologia e a inteligência aplicadas são extremamente importantes, pois essa é, muitas vezes, a principal camada de defesa contra ataques direcionados — que são os mais perigosos — ou até ataques mais genéricos, onde criminosos utilizam listas de e-mails vazadas para disparos em massa. A operação de um sistema de antimail é contínua e exige ajustes frequentes, já que nem sempre o problema será apenas phishing ou spam, mas também o uso indevido do e-mail corporativo, como cadastro em serviços pessoais (Spotify, Canva, entre outros). Dependendo da política da empresa, esses comportamentos devem ser monitorados ou bloqueados, garantindo maior controle e segurança do ambiente.
---