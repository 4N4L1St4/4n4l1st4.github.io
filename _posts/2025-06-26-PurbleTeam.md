---
title: "Checklist de CyberSeguranca"
date: 2025-06-26 16:30:00 -0300
categories: [Blue Team, Nivel 1]
tags: [Teorica]
description: "Aqui voce vai encontrar uma checklist baseado em uma arquitetura simulada, dependo da empresa voce poderá usar todos, e entendas as ideias para aplicar na sua realidade"
image:
  path: /assets/img/PROJsiem.png
  alt: Ilustração de um computador moderno com elementos de código e processamento
---

# 🔵 Blue Team: Introdução ao SIEM (conceito, uso, eventos)

Esse é o nosso diagrama para ter uma visão de como é o ambiente que estamos tendo

![Diagrama de Fluxo](/assets/img/DiagramaEstudo.svg)


## DIA x: 🔥 Revisão de Controles de Firewall: IPS

O IPS (Intrusion Prevention System) é um mecanismo fundamental de defesa que inspeciona o tráfego de rede em tempo real, com a capacidade de **bloquear automaticamente ataques conhecidos e comportamentos suspeitos** com base em assinaturas e análise de comportamento.

### ✅ Objetivos do dia:
- Validar se o IPS está **ativo** e **operando em modo de bloqueio**.
- Verificar a **atualização das assinaturas** de ataque.
- Analisar **alertas e bloqueios recentes** registrados no firewall.
- Ajustar **sensibilidade/tuning** para evitar falsos positivos e garantir máxima proteção.

### 🛠️ Itens a verificar:
- 🔄 Última atualização de regras e assinaturas.
- 🚫 Eventos bloqueados: tipo, origem, destino, horário.
- 🧠 Regras em modo “alerta” que deveriam estar em modo “bloqueio”.
- 🔍 Verificar logs de eventos: Exploração de vulnerabilidades, Port Scans, Ataques DoS, etc.
- 🧱 Integração com o SIEM: os eventos IPS estão sendo correlacionados?

### 🧩 Boas práticas:
- Mantenha o IPS sempre **atualizado com assinaturas recentes**.
- **Teste novas regras** em ambiente de homologação antes de ativar em produção.
- **Acompanhe os relatórios de desempenho**: o IPS pode impactar latência em redes de alto tráfego.
- Monitore **regras muito genéricas** que podem causar ruído ou bloqueios falsos.

### 🎯 Benefício principal:
Redução da superfície de ataque e **bloqueio automatizado de ameaças em tempo real**, antes mesmo de atingirem sistemas internos.

---

## DIA x: 🔥 Revisão de Controles de Firewall: IDS

## DIA x: 🔥 Revisão de Controles de Firewall: Ajustar Ordem

## DIA x: 🔥 Revisão de Controles de Firewall: Serviços publicados

## DIA x: 🔥 Revisão de Controles de Firewall: Revisar Portas conhecidas

## DIA x: 🔥 Revisão de Controles de Firewall: Remover regras desnecessarias

## DIA x: 🛡️ Revisão de Regras do WAF: Regras OWASP Top 10 ativadas

## DIA x: 🛡️ Revisão de Regras do WAF: Modo de operação (Detectar vs Bloquear)

## DIA x: 🛡️ Revisão de Regras do WAF: Proteção contra abuse de API

## DIA x: 🛡️ Revisão de Regras do WAF: Validação de parâmetros e payloads
Regras para validar campos POST/GET impedem ataques por injeção ou manipulação de variáveis.

## DIA x: 🛡️ Revisão de Regras do WAF: Atualizações automáticas do motor de regras
Mantenha o mecanismo do WAF atualizado com os últimos padrões de detecção e ameaças emergentes.

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - VMWare

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - Windows Server

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - Linux Server

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - Antivirus

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - WAF

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - Firewall

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - PAM

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - WAF

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - Router/SW

## DIA x: 🔐 Revisão Diária de Acessos Privilegiados (PAM): Validar rotação de senhas automáticas:
Confirme se o cofre de senhas está rotacionando as credenciais conforme programado (ex: a cada 24h ou por uso).

## DIA x: 🔐 Revisão Diária de Acessos Privilegiados (PAM): Validar rotação de senhas automáticas
Confirme se o cofre de senhas está rotacionando as credenciais conforme programado (ex: a cada 24h ou por uso).

## DIA x: 🔐 Revisão Diária de Acessos Privilegiados (PAM): Revisar máquinas que não tem controle de acesso

## DIA x: 🛡️ Monitoramento Diário de Antivírus: Verificar detecções recentes (últimas 24h)
Avalie alertas de malware, ransomware, trojans e PUPs (Programas Potencialmente Indesejados).

## DIA x: 🛡️ Monitoramento Diário de Antivírus: Confirmar cobertura total
Garanta que todos os endpoints tenham o agente instalado, atualizado e ativo. Atenção a hosts offline ou "inativos".

## DIA x: 🛡️ Monitoramento Diário de Antivírus: Revisar falhas de atualização de assinatura (dat, defs)
Verifique se algum host falhou ao atualizar as definições de vírus. Pode indicar falha de rede, proxy ou desinstalação.

## DIA x: 🛡️ Monitoramento Diário de Antivírus: Verificar arquivos colocados em quarentena
Avalie os arquivos isolados e sua origem. Itens persistentes podem indicar infecção ativa ou falso positivo.

## DIA x: 📧 Monitoramento Diário – Proteção de E-mail Corporativo: Monitorar regras de redirecionamento de e-mails em contas internas
Pode indicar manipulação de conta (ex: regra que copia tudo para Gmail externo).

## DIA x: 📧 Monitoramento Diário – Proteção de E-mail Corporativo: Investigar e-mails com anexos suspeitos
Avalie arquivos detectados com macros, scripts, ZIPs com senhas ou extensões duplas. Submeta à sandbox se necessário.

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Atualizar feed de IOC:
Importe as últimas listas de indicadores de fontes confiáveis (ex: MISP, AlienVault OTX, VirusTotal, Threat Intelligence Providers).

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Adicionar lista HASH em FW | AV | Email

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Adicionar lista URL em FW | AV | Email

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Adicionar lista IP ADDRES V4/V6 em FW | AV | Email

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Adicionar lista EMAIL em FW | AV | Email

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Realizar backup das bases de IOC:
Garanta a recuperação em caso de falhas ou perda de dados.

## DIA x: 🐝 Rotina Diária – Implantação e Manutenção de Honeypot: Extrair indicadores dos ataques capturados
Gere IOCs (IPs, domínios, payloads) para alimentar sistemas de defesa como SIEM e firewalls.

## DIA x: 🐝 Rotina Diária – Implantação e Manutenção de Honeypot: Extrair indicadores dos ataques capturados
Gere IOCs (IPs, domínios, payloads) para alimentar sistemas de defesa como SIEM e firewalls.

## DIA x: 🐝 Rotina Diária – Implantação e Manutenção de Honeypot: Monitorar alertas e notificações
Verifique se houve alertas críticos ou anomalias no ambiente do honeypot.

## DIA x: 🔍 Rotina Diária – Busca e Monitoramento de Data Leak: Validar e correlacionar dados encontrados:
Verifique se os dados vazados realmente pertencem à organização e avalie o impacto.

## DIA x: 🔍 Rotina Diária – Busca e Monitoramento de Data Leak: COletar dados de vazamentos
Atravez de telegra e sites de data leak

## DIA x: [RACI] Senhas Fracas ou Padrão	Risco: Utilização de senhas fracas, padrão (como "admin123") ou facilmente adivinháveis para contas de sistemas críticos.	Fazer um dump das senhas do AD para fazer um teste de força bruta por hash, validando a existencia de senhas popular e conhecidas.

## DIA x: [RACI] Senhas Fracas ou Padrão	Risco: Utilização de senhas fracas, padrão (como "admin123") ou facilmente adivinháveis para contas de sistemas críticos.	Fazer um dump das senhas do AD para fazer um teste de força bruta por hash, validando a existencia de senhas popular e conhecidas.

## DIA x: [RACI] Ausência de Revisão Periódica de Permissões	Risco: Permissões de acesso não são revisadas regularmente, permitindo que usuários mantenham acesso a sistemas mesmo quando não necessário.	Estamos falando a nivel de aplicações da 

## DIA x:[RVSA] Configurações Padrão ou Inseguras em Servidores e Aplicações	Risco: Sistemas operam com configurações padrão que não são otimizadas para segurança (ex: credenciais padrão, permissões excessivas).	Fazer um scan geral buscando por credencias padrão em aplicações (Threat Inteligence)
		

## DIA x:[RRC] Senhas Fracas em Dispositivos de Rede	Risco: Dispositivos de rede com senhas padrão ou fracas que não foram alteradas.	Fazer um scan geral buscando por credencias padrão em dispositivo de rede (Threat Inteligence)
		

## DIA x:[RRC] Exposição de Serviços Não Necessários	"Risco: Serviços desnecessários e portas abertas em servidores, expondo a rede a ataques.
-_Rede_10.10.0.0-24"	Atividade em busca de portas, seviços e usuarios padrão desnecessario
		

## DIA x:[RRC] Exposição de Serviços Não Necessários	"Risco: Serviços desnecessários e portas abertas em servidores, expondo a rede a ataques.
-_Rede_172.25.0.0-24"	Atividade em busca de portas, seviços e usuarios padrão desnecessario
		

## DIA x:[RRC] Exposição de Serviços Não Necessários	"Risco: Serviços desnecessários e portas abertas em servidores, expondo a rede a ataques.
-_Rede_172.30.0.0-24"	Atividade em busca de portas, seviços e usuarios padrão desnecessario
		

## DIA x:[RRC] Exposição de Serviços Não Necessários	"Risco: Serviços desnecessários e portas abertas em servidores, expondo a rede a ataques.
-_Rede_172.25.30.0-24"	Atividade em busca de portas, seviços e usuarios padrão desnecessario
		

## DIA x: Listagem_de_Credencias_em_Servidores_com_pastas_compartilhadas.pdf

## DIA x: Mikrotiks_sem_senha.pdf


## DIA x: Campanha Phising


## DIA x: Teste_de_Explor‡Æo_e_Movimento_Lateral_na_rede_de_Servidores_-_PT3.pdf


## DIA x: [RACI] Senhas Fracas ou Padrão	Risco: Utilização de senhas fracas, padrão (como "admin123") ou facilmente adivinháveis para contas de sistemas críticos.
	

## DIA x: [RACI] Falta de Controle de Acesso a Sistemas de Gestão	Risco: Contas com permissões administrativas em sistemas de gestão, como ERP ou CRM, são distribuídas sem critérios rigorosos.
	


## DIA x: [RRC] Falta de Segmentação de Rede	Risco: Redes internas não são devidamente segmentadas, permitindo que qualquer dispositivo se comunique com todos os outros.
	


## DIA x: [RGDC] Falta de Treinamento sobre Proteção de Dados	Risco: Colaboradores não são treinados adequadamente sobre práticas de segurança e proteção de dados.
	


## DIA x: [RCNPD] Falta de Treinamento e Simulações	Risco: Colaboradores não são treinados em procedimentos de continuidade e recuperação.

## DIA x: [RACI] Compartilhamento de Contas entre Usuários	Risco: Contas são compartilhadas entre vários colaboradores, dificultando a rastreabilidade de ações.	Criar regras no SIEM coletando eventos de autenticação e multi ferramentas de diversos origens com o mesmo usuario, coletando logs de eventos do clearclock, ad ...
		
		
## DIA x: [RACI] Política de Senhas Inadequada	Risco: Políticas de senha que permitem uso de caracteres simples, repetições e uso de senhas antigas.	Reforçar as senhas com criteriios mais rigorosos
		
		
## DIA x: [RRC] Exposição de Serviços Não Necessários	Risco: Serviços desnecessários e portas abertas em servidores, expondo a rede a ataques.	Fazer a limpa conforme ideia do josimar para serviços e portas desnecessaria em servidores em produção, apontando outras portas 
		
		
## DIA x: [RRC] Ataques de Spoofing e Interceptação de Pacotes	Risco: Redes não possuem proteção contra spoofing de IP ou ARP, permitindo ataques de interceptação.	Implantar execução de script em busca de spoof na rede, encaminhando para um serviço de monitoramento
		
		
## DIA x: Perfis&Sessoes_de_Usuarios_em_Desuso

 
## DIA x: Relatorio_-_Integracao_ERP_+_Web-Agent.pdf


## DIA x: Busca_por_Funcoes_de_Execucao_de_Comandos_Diretos_no_Sistema_Operacional_-_Projetos_no_SRVGIT.html


## DIA x: Coleta de logs referente ao ambiente oci


	




