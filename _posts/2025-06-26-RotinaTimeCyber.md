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

## DIA 01: Por que sua empresa não pode morar no seu notebook pessoal?

![Infraestrutura crítica rodando em um notebook pessoal representando risco de SPOF](/assets/img/dia01.png)
*Infraestrutura crítica não deve depender de um único equipamento de uso misto.*

Centralizar sistemas críticos em um equipamento pessoal representa um dos maiores riscos para o negócio. Todo começo tem limitações: muitas vezes a empresa "nasce" em um notebook, utilizando um serviço **SaaS** para gestão e armazenando arquivos financeiros e dados de clientes em apenas uma ou duas máquinas locais.

Nesse cenário, tudo compartilha o mesmo **link doméstico de 100 Mbps** e o mesmo roteador da operadora. Para completar o risco, o celular de uso pessoal (com redes sociais e apps de lazer) está pendurado no mesmo Wi-Fi que processa os dados sensíveis da pequena empresa.

### ⚠️ Pontos Críticos desta Arquitetura (O Diagnóstico do Caos)

Identificamos falhas que podem paralisar a operação em questão de segundos:

* **SPOF (Single Point of Failure):** O notebook é o "Ponto Único de Falha". Se ele queimar, for roubado ou infectado, a empresa para totalmente. Não há redundância.
* **Superfície de Ataque Ampliada:** O uso misto (pessoal e profissional) no mesmo hardware é perigoso. Um link malicioso acessado no lazer pode comprometer as credenciais do SaaS corporativo.
* **Rede Plana (Flat Network):** O roteador doméstico não isola os dispositivos. Se o celular pessoal for infectado por um malware, ele pode "escanear" o notebook na mesma rede e tentar exfiltrar dados dos clientes.
* **Inexistência de Backup Offline:** Dados guardados apenas no disco local ou em sincronizadores de nuvem sem controle de versão estão à mercê de falhas físicas ou Ransomwares.
* **Falta de SLA e Garantia:** Um link doméstico não tem garantia de disponibilidade. Uma instabilidade na operadora corta o acesso ao sistema principal, interrompendo o faturamento.

### 🎯 Objetivo do dia:
O objetivo é entender que a evolução é contínua. Nem toda empresa começa com a tecnologia de uma multinacional, mas a postura de segurança deve nascer cedo.

Compreender que **segurança começa pela disponibilidade e pela arquitetura correta do ambiente**. Reconhecer que o notebook pessoal e a rede doméstica são apenas uma fase que precisa de um plano de migração para o profissionalismo.

---