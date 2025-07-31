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

![Diagrama de Fluxo](/assets/img/DiagramaPRINCIPAL.svg)


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

O IDS (Intrusion Detection System) é um sistema de detecção passiva que monitora o tráfego de rede ou eventos de sistema, **identificando comportamentos suspeitos, ataques ou violações de política de segurança**, sem realizar bloqueios automáticos.

### ✅ Objetivos do dia:
- Confirmar que o IDS está **ativo e capturando eventos relevantes**.
- Analisar **alertas recentes** e identificar tendências ou repetições.
- Avaliar a **configuração das assinaturas de detecção**.
- Garantir que os alertas do IDS estão sendo **encaminhados para o SIEM**.

### 🛠️ Itens a verificar:
- 📅 Alertas das últimas 24h / 7 dias: scans de rede, brute-force, tráfego anômalo, etc.
- 🔄 Atualização das assinaturas de detecção.
- ⚠️ Volume de falsos positivos: ajustar regras ou tunar alertas recorrentes e irrelevantes.
- 📤 Verificação da integração com o SIEM ou ferramenta de correlação.
- 🎯 Identificar se há fontes não monitoradas (ex: segmentos de rede sem visibilidade IDS).

### 🧩 Boas práticas:
- Mantenha o IDS em **modo alerta apenas**, para evitar impactos operacionais.
- **Correlacione eventos IDS com logs de sistemas, endpoints e firewalls**.
- Acompanhe as estatísticas: tipos de ataque mais frequentes, IPs recorrentes, horários.
- Use o IDS como **fonte de inteligência para criação de regras no IPS ou firewall**.

### 🎯 Benefício principal:
O IDS amplia a visibilidade do time de segurança, ajudando na **identificação de ameaças que passam despercebidas por mecanismos de prevenção**.

---

## DIA x: 🔥 Revisão de Controles de Firewall: Ajustar Ordem

A ordem das regras no firewall impacta diretamente a **eficiência, desempenho e segurança** da rede. Em muitos firewalls, as regras são avaliadas de forma sequencial — da primeira até a última — até que uma condição seja atendida. Por isso, **regras mal posicionadas podem permitir tráfego indevido ou bloquear acessos legítimos**.

### ✅ Objetivos do dia:
- Avaliar a **sequência lógica** das regras aplicadas no firewall.
- Priorizar regras de **negação explícita**, regras mais genéricas ou de alta frequência.
- Eliminar **conflitos ou redundâncias** entre regras.
- Melhorar o **tempo de processamento** de pacotes.

### 🛠️ Itens a verificar:
- 📌 Regras mais genéricas (ex: "any-any") não devem estar antes de regras específicas.
- 🚫 Regras de bloqueio críticas devem estar no topo para ação imediata.
- 🧱 Agrupar regras por função (VPN, DMZ, usuários, servidores) facilita a leitura e manutenção.
- 🔄 Avaliar logs para identificar regras nunca acionadas ou fora de ordem.
- ⚠️ Evitar duplicidade ou sobreposição de regras.

### 🧩 Boas práticas:
- Mantenha **comentários/documentação nas regras**, explicando sua finalidade.
- Faça **backup da política atual** antes de reordenar.
- Use **ambientes de homologação** para testar alterações antes de aplicar em produção.
- Reavalie a ordem periodicamente, principalmente após alterações no ambiente.

### 🎯 Benefício principal:
Uma política de firewall bem ordenada garante **mais segurança com menos impacto em performance**, além de facilitar o gerenciamento futuro.

---

## DIA x: 🔥 Revisão de Controles de Firewall: Serviços publicados

A publicação de serviços para acesso externo representa uma **das maiores superfícies de ataque** em qualquer organização. Servidores web, portais de acesso remoto, APIs e VPNs precisam estar expostos com o **mínimo necessário e máxima proteção**.

### ✅ Objetivos do dia:
- Mapear todos os serviços que estão **expostos à internet** ou a redes de terceiros.
- Verificar se todos os serviços publicados **realmente precisam estar acessíveis** externamente.
- Validar se os serviços publicados estão **protegidos por WAF, VPN ou autenticação reforçada**.
- Confirmar se há **monitoramento e alertas ativos** para conexões externas.

### 🛠️ Itens a verificar:
- 🌐 Lista de NATs e regras de publicação no firewall (DNAT, Port Forward).
- 🔐 Serviços sem autenticação ou expostos em portas padrão (ex: 22, 3389, 80, 443) sem proteção adicional.
- 🧰 Publicações temporárias que foram esquecidas e continuam ativas.
- 🛡️ Verificar se o tráfego para serviços críticos passa por camadas extras (WAF, proxy, inspeção SSL).
- 📋 Documentar a justificativa de cada serviço publicado e o responsável por sua manutenção.

### 🧩 Boas práticas:
- **Minimizar a exposição**: publique apenas o necessário, evite expor painéis de administração.
- Use **VPN** para acesso remoto, sempre com autenticação multifator.
- Implemente **listas de IPs permitidos (whitelists)** sempre que possível.
- Realize **varreduras externas periódicas** (ex: Shodan, Nmap) para validar a exposição real.
- Mantenha todos os serviços expostos **atualizados** com os últimos patches de segurança.

### 🎯 Benefício principal:
Reduzir a superfície de ataque externa, dificultando a exploração por atacantes e melhorando a **postura de segurança perimetral**.

---

## DIA x: 🔥 Revisão de Controles de Firewall: Revisar Portas conhecidas

A exposição de portas conhecidas — como 22 (SSH), 3389 (RDP), 445 (SMB), 3306 (MySQL) — é uma das formas mais comuns de ataque em redes corporativas. Esses serviços são alvos frequentes de varreduras automáticas e ataques de força bruta.

### ✅ Objetivos do dia:
- Identificar todas as **portas padrão abertas** no firewall (internas e externas).
- Validar a **necessidade real** de cada serviço vinculado a essas portas.
- Verificar se há **serviços inseguros rodando em portas padrão**.
- Atualizar a documentação de **exceções** e justificativas.

### 🛠️ Itens a verificar:
- 📊 Levantamento completo das regras de firewall que permitem tráfego para portas bem conhecidas.
- 🔍 Inspeção de portas abertas para serviços internos (ex: RDP exposto internamente sem autenticação forte).
- 🔐 Existência de autenticação multifator ou tunneling (VPN) para portas como 22 e 3389.
- 🧱 Uso de firewalls de camada 7, proxies ou ACLs por IP para proteger os serviços.
- 🔁 Política de revisão periódica de regras e portas abertas.

### 🧩 Boas práticas:
- **Evite expor portas padrão externamente**, redirecione ou encapsule via VPN.
- Bloqueie portas de uso comum que não são utilizadas na sua rede.
- Utilize **sistemas de detecção de varredura (IDS/IPS)** para alertar sobre tentativas de acesso.
- Aplique **rate limiting** e lockout automático para serviços autenticados.
- Monitore tentativas de conexão por **SIEM ou logs de firewall**.

### 🎯 Benefício principal:
Reduz a exposição a ataques automatizados e impede que serviços internos sejam acessados sem controle, promovendo uma **postura de defesa em profundidade**.

---

## DIA x: 🔥 Revisão de Controles de Firewall: Remover regras desnecessárias

Firewalls ao longo do tempo acumulam regras temporárias, testes antigos e acessos que já não são mais necessários. Essa "sujeira" pode causar **riscos de segurança**, **confusão na administração** e até impacto na **performance** do dispositivo.

### ✅ Objetivos do dia:
- Localizar **regras obsoletas ou não utilizadas** no firewall.
- Validar com os responsáveis de sistemas se a regra ainda é necessária.
- Eliminar ou desabilitar regras que **não têm uso documentado ou monitorado**.
- Garantir que **cada regra existente tenha um propósito, dono e validade definida**.

### 🛠️ Itens a verificar:
- 📄 Regras criadas como *temporárias* (com nomes como "teste", "tmp", "liberado_urgente").
- 🧪 Regras sem tráfego registrado nos últimos 30 dias.
- 🔍 Regras duplicadas ou sobrepostas.
- ⚠️ Regras abertas demais (ex: `ANY > ANY` ou IPs e portas amplas).
- 📆 Regras com **prazo vencido**, mas ainda ativas.

### 🧩 Boas práticas:
- Implementar um **processo de revisão periódica (mensal/trimestral)** das regras de firewall.
- Utilizar **descrições claras e padronizadas** para cada regra (dono, propósito, data de criação).
- Aplicar o **princípio do menor privilégio**, removendo o que não for absolutamente necessário.
- Integrar o firewall ao **SIEM**, para identificar regras com zero eventos.

### 🎯 Benefício principal:
Reduz significativamente a **superfície de ataque** da organização, melhora a **eficiência operacional** e fortalece a **governança sobre os controles de rede**.

---

## DIA x: 🛡️ Revisão de Regras do WAF: Regras OWASP Top 10 ativadas

O WAF (Web Application Firewall) é uma camada essencial para proteger aplicações web. Ele atua bloqueando tráfego malicioso antes que atinja o servidor, com foco em ataques de aplicação (camada 7). Uma das formas mais eficazes de garantir proteção é manter as **regras baseadas na OWASP Top 10** devidamente ativadas e ajustadas.

### ✅ Objetivos do dia:
- Verificar se as regras do WAF que cobrem as vulnerabilidades da **OWASP Top 10** estão habilitadas.
- Validar se essas regras estão atualizadas, refinadas e com **falsos positivos sob controle**.
- Ajustar o nível de severidade, modo de operação (detecção/bloqueio) e alertas.

### 🔟 OWASP Top 10 (2021) a ser coberta pelo WAF:
- A01: Quebra de Controle de Acesso (Broken Access Control)
- A02: Criptografia Insegura (Cryptographic Failures)
- A03: Injeção (Injection - SQL, OS, LDAP)
- A04: Design Inseguro (Insecure Design)
- A05: Configuração de Segurança Incorreta
- A06: Componentes Vulneráveis e Desatualizados
- A07: Falhas de Identificação e Autenticação
- A08: Falhas em Log e Monitoramento
- A09: SSRF (Server-Side Request Forgery)
- A10: Falhas de Validação de Entrada (Input Validation)

### 🛠️ Itens práticos para revisar:
- 📌 O WAF está operando em **modo de bloqueio** para regras críticas?
- 🧪 Testar aplicações com payloads de exemplo para validar resposta do WAF.
- 📊 Consultar relatórios ou logs do WAF sobre eventos recentes relacionados às regras OWASP.
- ⚙️ Ajustar thresholds ou exceções para evitar **falsos positivos que afetam a operação**.
- 🧾 Garantir que cada regra ativada tenha um log associado no SIEM.

### 🔍 Ferramentas auxiliares:
- Ferramentas de testes como **OWASP ZAP**, **Burp Suite**, ou scripts com `curl` para validar comportamento das regras.
- Dashboards do WAF (como ModSecurity, F5 ASM, FortiWeb, Cloudflare WAF, etc.).

### 🎯 Benefício principal:
Garantir que sua aplicação esteja protegida contra as **principais ameaças conhecidas**, com visibilidade e controle refinado sobre os acessos.

---

## DIA x: 🛡️ Revisão de Regras do WAF: Modo de operação (Detectar vs Bloquear)

Um ponto crítico na administração de um Web Application Firewall (WAF) é o **modo de operação** em que ele está configurado: **detecção (monitoramento apenas)** ou **bloqueio (proteção ativa)**. A escolha entre esses dois modos impacta diretamente o equilíbrio entre **segurança e disponibilidade**.

---

### 🎯 Objetivo do dia:
Revisar e ajustar o modo de operação das regras do WAF com foco em segurança **sem causar impacto indevido** nos usuários legítimos.

---

### 🧩 Entendendo os Modos:

- 🔍 **Modo Detectar (Log Only / Monitor Mode)**  
  O WAF apenas registra os eventos suspeitos, **sem bloquear o tráfego**. Ideal para fases de testes, ajuste fino de regras e redução de falsos positivos.

- 🔒 **Modo Bloquear (Block Mode)**  
  O WAF intercepta e **impede que a solicitação suspeita chegue ao servidor**. Recomendado quando as regras estão bem ajustadas e testadas.

---

### 🛠️ Checklist de verificação:

- [ ] Quais regras estão em modo **apenas detecção**?
- [ ] Existem regras que **nunca foram convertidas para bloqueio** desde a implantação?
- [ ] Houve um aumento recente de falsos positivos ou impacto em sistemas críticos?
- [ ] O time de segurança está monitorando **corretamente os logs gerados** em modo detecção?
- [ ] Quais endpoints são mais sensíveis a bloqueios (como APIs, login, formulários etc.)?

---

### ⚖️ Estratégia recomendada:

1. **Comece com o modo "Detectar"** para novas regras.
2. Analise os logs no SIEM ou console do WAF por 7–15 dias.
3. Ajuste a regra para reduzir falsos positivos.
4. **Mude para o modo "Bloquear" gradualmente**, priorizando:
   - Regras do OWASP Top 10.
   - Injeção de SQL, XSS, LFI/RFI.
   - Requisições malformadas ou anômalas.

---

### 📈 Dica operacional:
Utilize **dashboards com alertas em tempo real** para eventos de detecção. Isso permite respostas rápidas antes de aplicar o modo bloqueio.

---

### 💡 Conclusão:
A maturidade do uso do WAF depende da capacidade da equipe em evoluir de um modo passivo (detecção) para um modo ativo (bloqueio), sem comprometer a usabilidade. Essa revisão periódica **é um marco importante na elevação da postura de segurança** da organização.

---

## DIA x: 🛡️ Revisão de Regras do WAF: Proteção contra abuso de API

APIs são alvos cada vez mais comuns em ataques automatizados e exploração de lógica de aplicação. O uso do WAF como **camada de defesa para APIs** precisa ir além das regras básicas — é preciso implementar controles específicos que previnam abuso, vazamento de dados e sobrecarga de recursos.

---

### 🎯 Objetivo do dia:
Verificar se o WAF está protegendo adequadamente os endpoints de API da organização, com foco em **uso abusivo, automação maliciosa e violações de autenticação/autorização**.

---

### 🧩 Tipos comuns de abuso de API:

- 📤 **Data scraping**: coleta automatizada de dados.
- 🔁 **Rate abuse**: chamadas excessivas ao endpoint (DoS, brute force, enumeração).
- 🔓 **Falhas de autenticação e autorização**.
- 🧪 **Fuzzing de parâmetros** em busca de vulnerabilidades.
- 🤖 **Bots não identificados** ou não autorizados.

---

### 🛠️ Checklist de proteção:

- [ ] O WAF está inspecionando tráfego de **APIs REST/JSON e SOAP/XML** corretamente?
- [ ] Há limites de requisição (rate limiting) configurados por IP, token ou chave de API?
- [ ] Existem regras específicas para detectar **métodos HTTP incomuns** (PUT, DELETE, etc.)?
- [ ] A autenticação está protegida contra **força bruta e credential stuffing**?
- [ ] Está sendo validado o **Content-Type, tamanho de payload e parâmetros esperados**?
- [ ] O tráfego automatizado é detectado via fingerprint ou challenge (reCAPTCHA, JS)?
- [ ] Há regras para bloquear ataques OWASP API Top 10 (2023)?

---

### 🔧 Boas práticas:

- Defina perfis de uso normal por endpoint e alerte desvios.
- Bloqueie usuários que excederem chamadas por tempo (throttling).
- Use JWT/token validation no WAF (se suportado).
- Habilite **logs detalhados por rota** de API.
- Considere uso de Web Application & API Protection (WAAP), se disponível.

---

### 📊 Indicadores úteis:

- Picos de chamadas fora do horário padrão.
- Alto volume de erros HTTP 401/403.
- Padrões de IPs ou agentes de usuário repetitivos.
- Tentativas de enumeração de recursos (`/api/user/1`, `/api/user/2`, ...)

---

### 💡 Conclusão:
Proteger APIs no WAF exige **granularidade e monitoração constante**. Com regras bem ajustadas, é possível bloquear abusos automatizados, proteger dados sensíveis e reduzir o risco de comprometimento por falhas de lógica de negócio.

---

## DIA x: 🛡️ Revisão de Regras do WAF: Validação de parâmetros e payloads

A validação de parâmetros e payloads no WAF é essencial para prevenir ataques que exploram vulnerabilidades em aplicações web, como injeção de SQL, Cross-Site Scripting (XSS), e manipulação de variáveis.

---

### 🎯 Objetivo do dia:
Garantir que o WAF esteja configurado para validar e filtrar corretamente todos os dados enviados pelos usuários, impedindo o envio de entradas maliciosas que possam comprometer a segurança da aplicação.

---

### 🛠️ Principais pontos a verificar:

- [ ] Configuração de regras que **validem todos os campos recebidos via GET, POST, HEAD, PUT, DELETE**, etc.
- [ ] Definição de **tipos de dados esperados** para cada parâmetro (ex: numérico, texto, email).
- [ ] Implementação de **listas brancas (whitelists)** para valores aceitos quando possível.
- [ ] Bloqueio de caracteres especiais e sequências usadas em ataques comuns (ex: `';--`, `<script>`, `../`).
- [ ] Limitação de tamanho para parâmetros para evitar buffer overflow e ataques DoS.
- [ ] Análise do conteúdo dos payloads para detectar scripts ou códigos maliciosos embutidos.
- [ ] Validação de cabeçalhos HTTP e cookies para evitar manipulações.
- [ ] Integração do WAF com a aplicação para atualização automática das regras conforme mudanças nos parâmetros.

---

### 🔧 Boas práticas:

- Use assinaturas atualizadas contra as vulnerabilidades mais recentes.
- Combine validação no WAF com validação no lado servidor para dupla proteção.
- Monitore logs do WAF para identificar tentativas de exploração falhas e ajustar regras.
- Realize testes de penetração para validar eficácia das regras.

---

### 📊 Indicadores de alerta:

- Requisições bloqueadas por parâmetros suspeitos.
- Aumento em erros HTTP 400 ou 403 relacionados a payloads.
- Padrões recorrentes de tentativas de injeção ou exploração de vulnerabilidades.

---

### 💡 Conclusão:
A validação rigorosa de parâmetros e payloads no WAF reduz drasticamente a superfície de ataque, protegendo as aplicações web contra uma grande variedade de ameaças conhecidas e emergentes.

---

## DIA x: 🛡️ Revisão de Regras do WAF: Atualizações automáticas do motor de regras

Manter o motor de regras do WAF (Web Application Firewall) atualizado é fundamental para garantir que o sistema esteja protegido contra as ameaças mais recentes e vulnerabilidades emergentes.

---

### 🎯 Objetivo do dia:
Garantir que o WAF esteja sempre com as últimas assinaturas e regras aplicadas, para maximizar a eficácia da proteção contra ataques conhecidos e novos vetores de ameaça.

---

### 🛠️ Pontos principais para revisão:

- [ ] **Verificar se as atualizações automáticas estão habilitadas e funcionando corretamente.**  
  Muitas soluções modernas de WAF oferecem atualização automática das regras, o que reduz o trabalho manual e melhora a rapidez da proteção.

- [ ] **Auditar logs de atualização** para confirmar que não houve falhas ou interrupções recentes.

- [ ] **Configurar alertas para falhas de atualização,** garantindo que a equipe seja notificada imediatamente em caso de problemas.

- [ ] **Validar a versão atual do motor de regras e compará-la com a última disponível pelo fornecedor.**

- [ ] **Planejar manutenção periódica para revisar customizações,** assegurando que regras manuais não sejam sobrescritas inadvertidamente durante as atualizações.

---

### 🔧 Boas práticas:

- Habilite atualizações automáticas, mas sempre monitore e valide os logs para evitar impactos inesperados na aplicação.

- Teste atualizações em ambientes controlados (staging) antes de aplicar em produção, se possível.

- Mantenha contato com o fornecedor para receber notificações sobre novas vulnerabilidades e atualizações críticas.

- Combine atualizações automáticas com revisões manuais para regras customizadas que atendam a necessidades específicas do negócio.

---

### 📊 Benefícios das atualizações automáticas:

- Proteção rápida contra novas ameaças e ataques.

- Redução do esforço manual e risco de esquecimento de atualização.

- Melhor alinhamento com padrões de segurança como OWASP Top 10.

---

### 💡 Conclusão:
As atualizações automáticas do motor de regras do WAF são um componente essencial para manter a defesa da aplicação web sempre atualizada e eficaz. A revisão periódica desse processo garante segurança contínua e minimiza riscos.

---

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - VMWare

O SIEM (Security Information and Event Management) é uma ferramenta crucial para a centralização e análise dos logs de segurança em um ambiente corporativo. A verificação diária da ingestão e das regras de logs provenientes do ambiente VMWare garante que eventos críticos sejam detectados e que a visibilidade sobre a infraestrutura virtual esteja sempre atualizada.

---

### 🎯 Objetivo do dia:
Assegurar que o SIEM está recebendo corretamente os logs do ambiente VMWare e que as regras de correlação estão funcionando para identificar eventos de segurança relevantes.

---

### 🛠️ Pontos principais para verificação:

- [ ] **Confirmar a ingestão de logs do VMWare no SIEM:**  
  Verifique se os logs do ESXi, vCenter Server e outros componentes do ambiente virtualizado estão sendo coletados sem falhas.

- [ ] **Checar a integridade e o timestamp dos logs:**  
  Certifique-se que os logs estão chegando em tempo real e com timestamps corretos para análise precisa.

- [ ] **Revisar regras de correlação específicas para VMWare:**  
  Avalie se as regras configuradas para eventos críticos, como falhas de autenticação, mudanças de configuração e criação/exclusão de máquinas virtuais, estão ativas e funcionando.

- [ ] **Monitorar alertas e notificações:**  
  Confirme se alertas relevantes estão sendo gerados para incidentes relacionados ao ambiente VMWare.

- [ ] **Verificar possíveis gaps na cobertura dos logs:**  
  Identifique se algum componente do ambiente virtual não está enviando logs para o SIEM.

---

### 🔧 Boas práticas:

- Mantenha os agentes ou conectores de logs do VMWare atualizados para garantir compatibilidade com o SIEM.

- Documente as fontes de logs e as regras implementadas para facilitar auditorias e futuras revisões.

- Realize testes periódicos de simulação de eventos para validar a eficácia das regras de detecção.

---

### 📊 Benefícios da verificação diária:

- Garantia de visibilidade contínua sobre o ambiente virtual.

- Detecção rápida de comportamentos anômalos ou tentativas de ataque.

- Melhoria na resposta a incidentes com dados confiáveis e atualizados.

---

### 💡 Conclusão:
Manter a ingestão e as regras de logs do VMWare atualizadas no SIEM é essencial para proteger ambientes virtualizados, que são cada vez mais críticos nas infraestruturas de TI modernas. A rotina diária de verificação permite antecipar riscos e manter a segurança do ambiente.

---

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - Windows Server

A verificação diária da ingestão de logs do Windows Server no SIEM é essencial para garantir a segurança e integridade do ambiente. O Windows Server gera diversos eventos críticos relacionados à autenticação, autorização, modificações de sistema, e atividades administrativas que precisam ser monitorados constantemente para detectar comportamentos suspeitos e responder a incidentes rapidamente.

### Principais passos para a verificação:

- **Confirmar a chegada dos logs:**  
  Verifique se os logs dos canais principais do Windows (Segurança, Sistema, Aplicativo, Diretivas de Grupo) estão sendo coletados e indexados corretamente no SIEM. A ausência desses dados pode indicar falhas no agente coletor ou problemas de rede.

- **Revisar as regras de correlação configuradas:**  
  Confira se as regras que geram alertas para eventos críticos, como tentativas de login falhas, criação/exclusão de contas, elevação de privilégios, alteração de políticas e instalação de software, estão ativas e funcionando.

- **Validar a sincronização do tempo:**  
  É fundamental que o timestamp dos eventos esteja correto. Servidores Windows devem estar sincronizados via NTP para garantir a precisão temporal das análises no SIEM.

- **Monitorar alertas de falha no serviço de logs:**  
  Problemas no serviço Windows Event Log ou no agente de coleta podem interromper a ingestão dos logs. Alertas sobre falhas devem ser investigados imediatamente.

- **Auditar a integridade dos logs:**  
  Sempre que possível, valide se os logs não foram alterados ou apagados, para manter a confiabilidade dos dados coletados.

### Benefícios dessa rotina diária:

- Garante visibilidade completa dos eventos de segurança do Windows Server.  
- Detecta atividades suspeitas e possíveis ataques em tempo hábil.  
- Facilita auditorias internas e externas com logs confiáveis e completos.  
- Contribui para a conformidade com políticas de segurança e regulamentações.

Manter essa rotina assegura que o SIEM funcione como uma ferramenta eficaz de detecção e resposta a incidentes, fortalecendo a postura de segurança da organização.

---

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - Linux Server

A verificação diária da ingestão de logs de servidores Linux no SIEM é fundamental para garantir a segurança, a detecção precoce de ameaças e a conformidade operacional. Os sistemas Linux geram uma variedade de logs importantes, incluindo autenticação, sistema, segurança e serviços específicos, que devem ser monitorados de forma consistente.

### Principais passos para a verificação:

- **Confirmar o recebimento dos logs:**  
  Verifique se os logs essenciais como `/var/log/auth.log`, `/var/log/syslog`, `/var/log/messages`, além de logs específicos de aplicações (por exemplo, Apache, SSH), estão sendo corretamente coletados e enviados para o SIEM.

- **Revisar regras de correlação e alertas:**  
  Confirme se as regras configuradas para eventos críticos — como tentativas falhas de login, escalonamento de privilégios, mudanças em arquivos sensíveis, conexões SSH anômalas, e falhas em serviços — estão ativas e gerando alertas adequados.

- **Sincronização de horário:**  
  Certifique-se de que o servidor Linux está sincronizado com um servidor NTP confiável para que os timestamps dos eventos estejam corretos e alinhados com outros dispositivos.

- **Monitorar falhas na coleta de logs:**  
  Identifique erros ou interrupções nos agentes de coleta (ex: rsyslog, syslog-ng, Filebeat) e resolva rapidamente para evitar lacunas no monitoramento.

- **Validar a integridade dos logs:**  
  Sempre que possível, implemente mecanismos para garantir que os logs não foram adulterados ou deletados, assegurando a confiabilidade das evidências coletadas.

### Benefícios desta rotina:

- Visibilidade clara e contínua dos eventos de segurança do ambiente Linux.  
- Identificação rápida de tentativas de invasão, erros críticos e problemas operacionais.  
- Suporte para auditorias de segurança e conformidade regulatória.  
- Melhoria da postura de segurança por meio da detecção e resposta proativas.

Manter essa rotina é crucial para garantir que o SIEM funcione eficazmente, oferecendo insights valiosos e fortalecendo a defesa do ambiente Linux contra ameaças e incidentes.

---

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - Antivirus

A verificação diária da ingestão dos logs de antivírus no SIEM é uma prática essencial para manter a segurança dos endpoints e garantir que as ameaças sejam rapidamente identificadas e mitigadas.

### Pontos importantes a verificar:

- **Confirmação da ingestão dos logs:**  
  Assegure que os logs de eventos de antivírus (detecções, quarentenas, atualizações de definição, varreduras completas/parciais) estejam sendo enviados corretamente ao SIEM.

- **Monitoramento de alertas críticos:**  
  Identifique e analise imediatamente eventos de infecção confirmada, tentativas de infecção bloqueadas, malware detectado, e falhas críticas no antivírus.

- **Verificação de atualizações:**  
  Garanta que todos os agentes de antivírus estejam atualizados com as últimas definições de vírus e software, pois agentes desatualizados reduzem a eficácia da proteção.

- **Status do agente:**  
  Verifique se todos os endpoints têm o agente antivírus ativo e reportando corretamente. Hosts com agentes desativados ou inativos representam risco elevado.

- **Análise de falsos positivos:**  
  Avalie os eventos repetitivos que podem ser falsos positivos para ajustar regras e evitar alertas excessivos que geram "ruído".

- **Falhas e erros:**  
  Monitorar eventos que indicam falhas na varredura, erros de instalação ou remoção de componentes do antivírus, e problemas na comunicação com o console central.

### Benefícios dessa rotina diária:

- Melhora a detecção precoce de ameaças e infecções em endpoints.  
- Reduz riscos de propagação de malware dentro da rede.  
- Facilita a resposta rápida e precisa a incidentes de segurança.  
- Auxilia na manutenção da conformidade regulatória e políticas internas de segurança.

Manter essa rotina garantirá que a proteção antivírus seja efetiva, que os logs sejam completos e confiáveis, e que o time de segurança tenha visibilidade clara sobre o estado dos endpoints.

---

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - WAF

O Web Application Firewall (WAF) é uma camada crítica de defesa para proteger aplicações web contra ataques como injeção SQL, cross-site scripting (XSS), e outras ameaças da OWASP Top 10. A integração dos logs do WAF no SIEM permite uma visão centralizada e análises avançadas de segurança.

### Atividades diárias para verificação:

- **Confirmação da ingestão dos logs do WAF:**  
  Certifique-se de que os logs de eventos (bloqueios, alertas, erros) estejam sendo recebidos corretamente pelo SIEM, evitando lacunas na visibilidade.

- **Análise das regras aplicadas:**  
  Verifique se as regras do WAF estão ativas e atualizadas, incluindo assinaturas baseadas em padrões OWASP Top 10 e customizações específicas para a aplicação.

- **Monitoramento de eventos críticos:**  
  Identifique bloqueios repetidos e tentativas de ataques (como SQLi, XSS, file inclusion) para investigação rápida e resposta efetiva.

- **Validação da sincronização do tempo:**  
  Confirme que o horário dos logs do WAF está sincronizado com o SIEM para correlação correta dos eventos.

- **Avaliação de falsos positivos:**  
  Analise alertas que podem ser falsos positivos para ajustar regras e evitar o excesso de alarmes, mantendo a qualidade da detecção.

- **Verificação da performance e disponibilidade:**  
  Monitore se o WAF está operando corretamente sem impactar a disponibilidade das aplicações web.

### Benefícios dessa rotina:

- Melhora a proteção contra ataques direcionados a aplicações web.  
- Facilita a correlação de eventos com outras fontes no SIEM para melhor investigação.  
- Reduz o risco de exposição de vulnerabilidades através da camada de aplicação.  
- Auxilia na auditoria e conformidade de segurança das aplicações.

Manter a ingestão e monitoramento eficaz dos logs do WAF é fundamental para um ambiente web seguro e para a resposta rápida a incidentes.

---

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - Firewall

Os firewalls são a primeira linha de defesa para proteger a rede contra acessos não autorizados e ataques externos. Integrar os logs de firewall ao SIEM é essencial para garantir visibilidade completa sobre o tráfego de rede e identificar atividades suspeitas.

### Atividades diárias para verificação:

- **Confirmação da ingestão dos logs de firewall:**  
  Verifique se os logs estão sendo corretamente enviados e recebidos pelo SIEM, sem falhas ou interrupções, garantindo que todos os eventos de tráfego estejam sendo monitorados.

- **Validação das regras aplicadas no firewall:**  
  Assegure que as políticas e regras de firewall estejam atualizadas, alinhadas com a política de segurança da organização e que estejam refletidas corretamente nos logs.

- **Monitoramento de eventos críticos:**  
  Fique atento a tentativas de conexão bloqueadas, acessos não autorizados, tráfego anômalo e possíveis ataques, como varreduras (scans), tentativas de brute force, ou uso de portas não autorizadas.

- **Análise de tendências e picos de tráfego:**  
  Identifique padrões incomuns no tráfego de rede, que podem indicar tentativas de ataque ou comprometimento.

- **Correlação com outras fontes de dados no SIEM:**  
  Combine os eventos de firewall com logs de endpoints, servidores e aplicações para uma visão mais ampla dos incidentes de segurança.

- **Revisão de alertas e falsos positivos:**  
  Ajuste regras e filtros para evitar excesso de alertas, mantendo o foco em eventos relevantes e críticos.

### Benefícios dessa rotina:

- Garante a integridade e eficácia das políticas de firewall.  
- Melhora a capacidade de detecção e resposta a incidentes de rede.  
- Reduz o risco de intrusão e vazamento de dados.  
- Facilita auditorias e conformidade com normas de segurança.

Manter a ingestão e monitoramento contínuo dos logs de firewall no SIEM é fundamental para a proteção da infraestrutura de rede e segurança global da organização.

---

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - PAM

O PAM (Privileged Access Management) é essencial para controlar, monitorar e proteger acessos privilegiados, reduzindo riscos de abuso e comprometimento de credenciais críticas.

### Atividades diárias para verificação:

- **Confirmação da ingestão dos logs do PAM no SIEM:**  
  Verifique se todos os eventos relacionados a acessos privilegiados — como logins, sessões iniciadas, comandos executados e alterações em permissões — estão sendo capturados corretamente pelo SIEM.

- **Monitoramento de acessos incomuns:**  
  Identifique tentativas de acesso fora do horário comercial, por usuários não autorizados ou de localizações inesperadas.

- **Verificação de falhas de autenticação:**  
  Observe múltiplas tentativas falhas, que podem indicar tentativas de brute force ou comprometimento de contas privilegiadas.

- **Auditoria de sessões privilegiadas:**  
  Certifique-se que as sessões são auditadas, gravadas e que os comandos executados estejam sendo registrados para análise futura.

- **Revisão de alterações em permissões e políticas:**  
  Detecte modificações nos níveis de acesso, criação ou exclusão de contas privilegiadas.

- **Correlação com eventos de outros sistemas:**  
  Correlacione os logs de PAM com eventos do firewall, antivírus e endpoint para identificar comportamentos suspeitos.

### Benefícios dessa rotina:

- Melhora a visibilidade sobre o uso das credenciais privilegiadas.  
- Auxilia na detecção rápida de abusos ou acessos indevidos.  
- Garante conformidade com políticas internas e regulações externas.  
- Facilita investigações forenses em caso de incidentes.

Manter a ingestão e o monitoramento contínuo dos logs do PAM no SIEM fortalece a postura de segurança da organização ao proteger os acessos mais sensíveis.

---

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - WAF

O WAF (Web Application Firewall) é uma camada importante para proteção das aplicações web, bloqueando ataques comuns como injeção SQL, XSS, e exploração de vulnerabilidades conhecidas.

### Atividades diárias para verificação:

- **Confirmar ingestão contínua dos logs do WAF no SIEM:**  
  Verifique se os logs de bloqueios, alertas e eventos do WAF estão sendo corretamente recebidos e indexados no SIEM para análise.

- **Analisar eventos críticos e bloqueios:**  
  Observe tentativas de ataques como injeção, exploração de vulnerabilidades, acessos não autorizados e tráfego anômalo bloqueado pelo WAF.

- **Monitorar alertas de falsos positivos:**  
  Identifique possíveis falsos positivos que possam impactar usuários legítimos e ajuste regras para minimizar interrupções sem comprometer a segurança.

- **Revisar tendências de ataque:**  
  Avalie padrões emergentes de ataques que podem indicar tentativas de exploração direcionadas contra a aplicação.

- **Garantir atualizações e sincronização das regras do WAF:**  
  Verifique se o motor do WAF está atualizado com as últimas assinaturas e regras de segurança para manter a eficácia da proteção.

- **Correlacionar eventos do WAF com outras fontes:**  
  Relacione dados do WAF com logs de firewall, IDS/IPS e sistemas endpoint para uma visão integrada dos incidentes.

### Benefícios dessa rotina:

- Melhora a detecção e resposta a ataques contra aplicações web.  
- Reduz o risco de comprometimento de dados e serviços online.  
- Ajusta continuamente a proteção para balancear segurança e experiência do usuário.  
- Suporta análises forenses e compliance.

Manter o monitoramento diário da ingestão e análise dos logs do WAF no SIEM fortalece a segurança das aplicações web e ajuda a antecipar ameaças.

---

## DIA x: 📊 Verificação Diária no SIEM: Verificar ingestão/regras de logs - Router/SW

Os dispositivos de rede como roteadores (Router) e switches (SW) são elementos críticos na infraestrutura, sendo fundamentais para a conectividade e segurança do ambiente.

### Atividades diárias para verificação:

- **Confirmar ingestão contínua dos logs de Router e Switch no SIEM:**  
  Verifique se os logs de eventos, alertas, e status desses dispositivos estão sendo corretamente recebidos e processados no SIEM.

- **Monitorar eventos críticos e anomalias:**  
  Preste atenção a logs que indicam falhas de hardware, alterações de configuração, tentativas de acesso não autorizadas, mudanças de rotas ou loops de rede.

- **Revisar logs de autenticação e acesso remoto:**  
  Verifique entradas de acesso via SSH, Telnet, VPN e outros métodos para garantir que só usuários autorizados estão conectados.

- **Detectar possíveis ataques de rede:**  
  Identifique atividades suspeitas como ataques DoS/DDoS, varreduras de portas, ou tráfego anômalo que possam indicar tentativa de invasão.

- **Validar sincronização de horário (NTP):**  
  Confirme que os dispositivos estão com horário correto para garantir precisão dos logs e facilitar correlação de eventos.

- **Garantir a aplicação das regras de segurança:**  
  Cheque se as ACLs (Access Control Lists), filtros e outras políticas de segurança estão ativas e funcionando conforme esperado.

- **Correlacionar eventos com outras fontes:**  
  Integre os dados de Router/Switch com logs de firewall, IDS/IPS e sistemas endpoint para uma análise completa da postura de segurança.

### Benefícios dessa rotina:

- Melhora a visibilidade da infraestrutura de rede no ambiente de segurança.  
- Ajuda na detecção precoce de incidentes que possam comprometer a disponibilidade e integridade da rede.  
- Apoia a investigação e resposta rápida a eventos de segurança.  
- Garante a conformidade com políticas e normas de segurança da empresa.

Manter essa rotina diária de verificação da ingestão e análise dos logs de dispositivos de rede no SIEM é fundamental para uma postura robusta de segurança e operação eficiente.

---

## DIA x: 🔐 Revisão Diária de Acessos Privilegiados (PAM): Validar rotação de senhas automáticas

A gestão adequada de acessos privilegiados é um dos pilares da segurança em ambientes corporativos. A rotação automática de senhas garante que credenciais sensíveis não permaneçam válidas por tempo excessivo, minimizando o risco de uso indevido.

### O que verificar diariamente:

- **Confirmação do funcionamento do sistema de rotação:**  
  Certifique-se que o PAM está realizando a troca automática das senhas conforme o período definido (exemplo: a cada 24 horas, semanalmente, ou após uso).

- **Verificação dos logs de rotação:**  
  Analise os registros para identificar falhas, erros ou senhas que não foram rotacionadas no tempo esperado.

- **Auditoria de acessos após a rotação:**  
  Garanta que o acesso às contas privilegiadas só seja possível com as novas credenciais e que não existam acessos com credenciais antigas.

- **Notificação de erros ou alertas:**  
  Configure alertas para notificar a equipe de segurança caso haja falhas na rotação ou tentativas suspeitas de acesso.

- **Confirmação da integração com sistemas dependentes:**  
  Verifique se aplicações, serviços e scripts que usam credenciais privilegiadas estão atualizados para usar as novas senhas.

### Por que isso é importante?

- **Reduz o risco de comprometimento:**  
  Senhas que permanecem fixas por muito tempo aumentam o risco de vazamento e uso indevido.

- **Atende a requisitos de conformidade:**  
  Muitas normas e frameworks de segurança exigem a rotação periódica de credenciais privilegiadas.

- **Mantém o controle e auditoria:**  
  Garante rastreabilidade e controle sobre quem acessa o quê, quando e como.

### Dicas para melhorar a rotação automática:

- Utilize um cofre de senhas (Password Vault) integrado ao PAM para gerenciar as credenciais centralizadamente.  
- Automatize a notificação e geração de relatórios periódicos para facilitar o acompanhamento.  
- Realize testes periódicos de acesso com as credenciais rotacionadas para validar o funcionamento.  

Manter essa rotina diária é fundamental para evitar vulnerabilidades associadas a acessos privilegiados e fortalecer a segurança da infraestrutura.

---

## DIA x: 🔐 Revisão Diária de Acessos Privilegiados (PAM): Revisar máquinas que não têm controle de acesso

Garantir que todas as máquinas críticas estejam sob o controle do sistema PAM é essencial para minimizar riscos relacionados a acessos privilegiados não monitorados.

### Pontos para revisão diária:

- **Inventário das máquinas com acesso privilegiado:**  
  Verifique a lista atualizada de servidores, estações e dispositivos que devem estar sob gerenciamento do PAM.

- **Identificação de máquinas fora do controle:**  
  Localize e registre máquinas que ainda não estão integradas ao PAM ou que possuem acessos privilegiados sem monitoramento.

- **Avaliação de riscos associados:**  
  Avalie o impacto potencial de máquinas sem controle, considerando dados sensíveis, serviços críticos e exposição a ameaças.

- **Ações para inclusão no PAM:**  
  Priorize a integração dessas máquinas ao sistema PAM, configurando agentes, credenciais e políticas de acesso.

- **Verificação de exceções autorizadas:**  
  Documente e valide casos onde máquinas estão fora do controle por decisão de negócio ou tecnicamente inviáveis, garantindo compensações de segurança.

- **Monitoramento contínuo:**  
  Estabeleça alertas para detectar novas máquinas que entrem no ambiente sem controle PAM.

### Por que essa revisão é crítica?

- **Prevenção contra acessos não autorizados:**  
  Máquinas sem controle podem ser portas de entrada para ataques privilegiados.

- **Conformidade regulatória:**  
  Normas exigem controle rigoroso sobre contas privilegiadas em toda a infraestrutura.

- **Fortalecimento da postura de segurança:**  
  Aumenta a visibilidade e reduz a superfície de ataque potencial.

### Dicas para facilitar o controle:

- Automatize a descoberta de máquinas na rede para identificar ativos não gerenciados.  
- Integre o PAM com sistemas de inventário e CMDB para manter dados atualizados.  
- Realize treinamentos e conscientização para equipes responsáveis sobre a importância do controle PAM.  

Manter essa rotina garante que o ambiente corporativo tenha o menor número possível de lacunas no controle de acessos privilegiados.

---

## DIA x: 🛡️ Monitoramento Diário de Antivírus: Verificar detecções recentes (últimas 24h)

O monitoramento constante das detecções do antivírus é uma atividade essencial para a proteção da rede e dos endpoints contra ameaças atuais.

### Principais pontos a verificar:

- **Analisar alertas e eventos de malware:**  
  Revise as detecções registradas nas últimas 24 horas, incluindo vírus, trojans, ransomware, worms e spyware.

- **Identificar padrões e reincidências:**  
  Verifique se as mesmas ameaças estão aparecendo repetidamente em um ou mais hosts, o que pode indicar uma infecção persistente ou falha na mitigação.

- **Avaliar falsos positivos:**  
  Diferencie entre alertas legítimos e falsos positivos para evitar ações desnecessárias que possam impactar o ambiente.

- **Verificar origem e vetor da ameaça:**  
  Identifique como a ameaça entrou no ambiente — e-mail, download, dispositivo removível, etc. Isso ajuda a ajustar controles preventivos.

- **Analisar status dos agentes antivírus:**  
  Confirme se todos os endpoints estão comunicando corretamente e reportando eventos, evitando lacunas na proteção.

- **Ações imediatas recomendadas:**  
  - Isolar máquinas infectadas para evitar propagação.  
  - Iniciar processo de remoção e limpeza.  
  - Atualizar definições e assinaturas de vírus.  
  - Documentar incidentes e comunicar as equipes responsáveis.

### Benefícios do monitoramento diário:

- Resposta rápida a incidentes de segurança.  
- Redução do impacto de ataques por contenção precoce.  
- Melhoria contínua das políticas e mecanismos de defesa.  

Manter esse acompanhamento diário ajuda a fortalecer a postura de segurança e a garantir que o antivírus esteja cumprindo seu papel de defesa ativa.

---

## DIA x: 🛡️ Monitoramento Diário de Antivírus: Confirmar cobertura total

Garantir a cobertura completa do antivírus em todos os endpoints da rede é fundamental para evitar brechas que possam ser exploradas por agentes maliciosos.

### Pontos essenciais para essa verificação:

- **Confirmação da instalação do agente antivírus:**  
  Verifique se todos os computadores, servidores, dispositivos móveis e estações de trabalho possuem o agente antivírus instalado.

- **Status do agente:**  
  Certifique-se que o antivírus está ativo e funcionando corretamente em cada endpoint, sem erros ou falhas de serviço.

- **Atualização das definições e versões:**  
  Confira se as definições de vírus (assinaturas) estão atualizadas e se o software está rodando a versão mais recente, garantindo eficácia contra ameaças novas.

- **Identificação de hosts offline ou inativos:**  
  Liste dispositivos que estejam desconectados da rede ou com agentes que não se comunicam há muito tempo, pois podem estar vulneráveis.

- **Análise de exceções e exclusões:**  
  Revise as configurações de exclusões para evitar que arquivos maliciosos sejam ignorados inadvertidamente.

- **Automação de alertas:**  
  Configure alertas para notificá-lo imediatamente sobre hosts que fiquem offline, sem atualização ou com falha no antivírus.

### Benefícios de manter cobertura total:

- Minimiza pontos cegos que podem ser explorados por malware.  
- Facilita a resposta rápida a ameaças e infecções.  
- Garante conformidade com políticas de segurança internas e regulatórias.

Manter essa rotina assegura uma postura defensiva robusta, com máxima proteção em toda a infraestrutura de TI.

---

## DIA x: 🛡️ Monitoramento Diário de Antivírus: Revisar falhas de atualização de assinatura (dat, defs)

Manter as definições de vírus atualizadas é essencial para que o antivírus detecte as ameaças mais recentes. Falhas nas atualizações podem deixar os sistemas vulneráveis a malwares novos e variantes.

### O que verificar:

- **Relatórios de atualização:**  
  Analise os logs ou dashboards da solução antivírus para identificar hosts que falharam em atualizar suas assinaturas (arquivos .dat, defs ou equivalentes).

- **Causas comuns das falhas:**  
  - Problemas de conectividade com a internet ou servidores proxy.  
  - Configurações incorretas no endpoint ou no antivírus.  
  - Conflitos com firewalls bloqueando o acesso ao servidor de atualização.  
  - Desinstalação parcial ou corrupção do agente antivírus.

- **Impacto:**  
  Hosts sem definições atualizadas podem não detectar ameaças novas, colocando a rede em risco.

### Ações recomendadas:

- **Identificar e contatar os responsáveis pelos hosts afetados:**  
  Solicitar a verificação manual da conexão e reinstalação do agente se necessário.

- **Verificar políticas e regras de rede:**  
  Garantir que servidores de atualização do antivírus não estejam bloqueados.

- **Automatizar alertas:**  
  Configurar notificações para quando um endpoint falhar em atualizar por um período definido (ex: 24h).

- **Testar atualização manual:**  
  Em alguns casos, realizar uma atualização manual no endpoint para validar a resolução do problema.

### Benefícios da rotina:

- Mantém a proteção eficaz contra ameaças emergentes.  
- Evita janelas de vulnerabilidade por falta de atualização.  
- Auxilia na manutenção da saúde geral da infraestrutura de segurança.

---

## DIA x: 🛡️ Monitoramento Diário de Antivírus: Verificar arquivos colocados em quarentena

A quarentena é um recurso fundamental do antivírus para isolar arquivos suspeitos e impedir que causem danos ao sistema. Monitorar os arquivos isolados ajuda a entender o que está sendo detectado e tomar ações apropriadas.

### O que verificar:

- **Lista de arquivos em quarentena:**  
  Revise periodicamente os arquivos que foram colocados em quarentena pelo antivírus, identificando o nome, caminho, data da detecção e tipo de ameaça.

- **Origem dos arquivos:**  
  Tente entender a origem dos arquivos suspeitos — se vieram de downloads, anexos de e-mail, mídias removíveis ou processos internos.

- **Persistência de arquivos em quarentena:**  
  Itens que aparecem repetidamente ou que não podem ser removidos podem indicar infecção ativa ou tentativa de persistência de malware.

- **Falsos positivos:**  
  Avalie se algum arquivo legítimo foi isolado incorretamente para evitar interrupções desnecessárias nos negócios.

### Ações recomendadas:

- **Analisar arquivos suspeitos:**  
  Se possível, submeta os arquivos a ferramentas de sandbox ou serviços de análise para confirmar se são realmente maliciosos.

- **Remoção ou restauração:**  
  Remova definitivamente os arquivos confirmados como maliciosos para eliminar a ameaça. Restaure os falsos positivos após confirmação.

- **Investigar fontes de infecção:**  
  Caso haja múltiplos arquivos suspeitos de mesma origem, investigue processos, usuários ou máquinas que possam estar comprometidos.

- **Documentar ocorrências:**  
  Mantenha registro das quarentenas para histórico e análise de tendências de ameaças.

### Benefícios da rotina:

- Melhora a visibilidade sobre as ameaças detectadas no ambiente.  
- Ajuda a evitar falsos positivos impactantes para a operação.  
- Identifica possíveis infecções ativas para resposta rápida.  
- Contribui para o fortalecimento contínuo da segurança do endpoint.

---

## DIA x: 📧 Monitoramento Diário – Proteção de E-mail Corporativo: Monitorar regras de redirecionamento de e-mails em contas internas

As regras de redirecionamento em contas de e-mail corporativo podem ser um vetor silencioso para vazamento de informações ou comprometimento da conta. Monitorar essas regras é essencial para detectar manipulações maliciosas que podem passar despercebidas pelos usuários.

### Por que monitorar regras de redirecionamento?

- **Detecção de acesso não autorizado:**  
  Regras que redirecionam e-mails para endereços externos (exemplo: Gmail, Yahoo) podem indicar que uma conta foi comprometida.

- **Prevenção de vazamento de dados:**  
  Informações sensíveis podem ser enviadas automaticamente para terceiros mal-intencionados sem que o usuário perceba.

- **Identificação de ataques de engenharia social:**  
  Invasores podem criar regras para monitorar comunicações e planejar ataques mais sofisticados.

### O que verificar diariamente?

- **Listagem das regras de redirecionamento configuradas:**  
  Verifique todas as regras configuradas para encaminhamento ou cópia automática de e-mails.

- **Destinatários externos:**  
  Atente para endereços de e-mail fora do domínio da empresa, principalmente domínios públicos.

- **Novas regras criadas:**  
  Compare as regras atuais com a base histórica para identificar inclusões recentes e suspeitas.

- **Contas afetadas:**  
  Avalie se múltiplas contas apresentam regras suspeitas, indicando possível comprometimento em larga escala.

### Ações recomendadas:

- **Investigar usuários com regras suspeitas:**  
  Contate os usuários para confirmar se as regras foram configuradas por eles.

- **Remover regras maliciosas:**  
  Apague imediatamente as regras não autorizadas para evitar vazamento contínuo.

- **Alterar senhas e habilitar MFA:**  
  Para contas comprometidas, force troca de senha e ative autenticação multifator para mitigar riscos futuros.

- **Gerar alertas automáticos:**  
  Configure o sistema de e-mail para disparar alertas em caso de criação/modificação de regras de redirecionamento.

### Benefícios da rotina:

- Mantém o ambiente de e-mail seguro contra ataques silenciosos.  
- Evita perdas de informações críticas por canais não monitorados.  
- Auxilia na rápida detecção e resposta a comprometimentos.  
- Promove maior conscientização dos usuários sobre segurança do e-mail.

---

## DIA x: 📧 Monitoramento Diário – Proteção de E-mail Corporativo: Investigar e-mails com anexos suspeitos

O monitoramento e a investigação de e-mails com anexos suspeitos são essenciais para prevenir ataques de malware, phishing e comprometimento da rede corporativa.

### Por que investigar anexos suspeitos?

- **Macros maliciosas:**  
  Arquivos do Office com macros podem executar códigos maliciosos ao serem abertos.

- **Scripts escondidos:**  
  Anexos que contenham scripts (VBScript, PowerShell, JavaScript) podem ser usados para infectar o sistema.

- **Arquivos ZIP protegidos por senha:**  
  Muitas vezes usados para burlar filtros de segurança, esses arquivos podem conter malware que só será detectado após a extração.

- **Extensões duplas (ex: .pdf.exe):**  
  Técnicas para enganar usuários mostrando uma extensão aparentemente inofensiva.

### O que fazer na rotina diária?

- **Analisar alertas do sistema de e-mail:**  
  Fique atento a mensagens marcadas como potencialmente perigosas pelo filtro antispam/antimalware.

- **Verificar a reputação dos remetentes:**  
  Priorize a análise de remetentes desconhecidos ou suspeitos.

- **Submeter anexos suspeitos para análise em sandbox:**  
  Utilize ambientes isolados para executar e monitorar o comportamento dos arquivos.

- **Validar assinaturas digitais:**  
  Confirme se o arquivo possui assinatura válida de remetentes confiáveis.

- **Comunicar o usuário afetado:**  
  Caso o anexo seja malicioso, oriente o usuário para não abrir anexos similares e revisar boas práticas.

### Ferramentas recomendadas:

- Sistemas de sandbox como Cuckoo Sandbox, FireEye, ou serviços na nuvem (VirusTotal, Hybrid Analysis).  
- Soluções de e-mail corporativo com proteção avançada contra ameaças (ATP).  
- Ferramentas de análise estática e dinâmica de malware.

### Benefícios da rotina:

- Redução do risco de infecção por malware.  
- Detecção precoce de tentativas de phishing e engenharia social.  
- Aumento da segurança e confiança no ambiente de e-mail corporativo.  
- Melhoria contínua nas políticas e filtros antimalware.

---

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Atualizar feed de IOC

A atualização diária das listas de Indicadores de Comprometimento (IOCs) é fundamental para manter a defesa da organização sempre alinhada às ameaças mais recentes.

### Por que atualizar os feeds de IOC?

- **Identificação rápida de ameaças:**  
  Os IOCs incluem endereços IP maliciosos, hashes de arquivos, domínios suspeitos, URLs e e-mails usados em ataques recentes.

- **Prevenção e detecção eficaz:**  
  Com IOCs atualizados, firewalls, antivírus, SIEMs e outros sistemas podem bloquear ou alertar sobre tentativas de ataque conhecidas.

- **Compartilhamento de inteligência:**  
  Fontes como MISP (Malware Information Sharing Platform), AlienVault OTX e VirusTotal reúnem informações globais sobre ameaças.

### Como executar a rotina?

1. **Automatizar a importação dos feeds:**  
   Configure scripts ou conectores para baixar e integrar automaticamente os dados das fontes confiáveis.

2. **Validar integridade dos dados:**  
   Garanta que os feeds estejam completos e sem erros para evitar falhas na ingestão.

3. **Atualizar as bases de dados dos sistemas de defesa:**  
   Inclua os novos IOCs no SIEM, firewall, antivírus e outros sistemas que suportam bloqueios baseados em IOCs.

4. **Monitorar a aplicação dos novos indicadores:**  
   Verifique logs e alertas para confirmar que os IOCs estão sendo utilizados na detecção e prevenção.

5. **Revisar periodicamente as fontes:**  
   Avalie se as fontes continuam relevantes e confiáveis para a organização.

### Benefícios da rotina:

- Defesa proativa contra ameaças emergentes.  
- Redução do tempo de resposta a incidentes.  
- Melhoria na eficácia dos sistemas de segurança.  
- Fortalecimento do ambiente de TI contra ataques direcionados.

---

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Adicionar lista HASH em FW | AV | Email

A adição diária de listas de hashes de arquivos maliciosos é essencial para ampliar a proteção dos sistemas contra malware conhecido e ameaças persistentes.

### O que é uma lista HASH?

- Conjunto de valores hash (MD5, SHA1, SHA256) que representam arquivos maliciosos ou indesejados.
- Usadas para identificar e bloquear arquivos que correspondem a ameaças já catalogadas.

### Por que adicionar listas de HASH?

- **Detecção precisa:** Permite identificar arquivos maliciosos pelo seu conteúdo, mesmo que o nome ou local mudem.
- **Bloqueio proativo:** Impede a execução ou transmissão de arquivos infectados na rede.
- **Integração com múltiplos sistemas:** Firewalls, antivírus e sistemas de e-mail podem usar essas listas para proteger diferentes pontos da infraestrutura.

### Como realizar essa rotina?

1. **Obter listas HASH atualizadas:**  
   Baixe listas confiáveis de fontes reconhecidas de Threat Intelligence, como MISP, AlienVault OTX, VirusTotal, ou feeds próprios.

2. **Formatar as listas conforme a necessidade do sistema:**  
   Cada ferramenta pode exigir formatos específicos (CSV, TXT, JSON). Adapte para importação correta.

3. **Importar as listas nas soluções de segurança:**  
   - **FW (Firewall):** para bloqueio de arquivos em transferência.  
   - **AV (Antivírus):** para detecção e quarentena.  
   - **Email Security:** para bloqueio de anexos maliciosos.

4. **Verificar a aplicação e funcionamento:**  
   Confirme via logs e dashboards que as listas foram aplicadas e que os sistemas estão ativos.

5. **Monitorar alertas e falsos positivos:**  
   Ajuste as listas caso haja bloqueios indevidos para evitar impactos no negócio.

### Benefícios:

- Melhora na capacidade de identificação e bloqueio de malware conhecido.  
- Redução de riscos por arquivos maliciosos em diversos vetores de ataque.  
- Sinergia entre diferentes camadas de segurança para proteção integrada.

---

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Adicionar lista URL em FW | AV | Email

Manter listas atualizadas de URLs maliciosas ou suspeitas é crucial para proteger a infraestrutura contra ameaças baseadas em web, como phishing, downloads de malware e sites comprometidos.

### O que é uma lista de URL?

- Conjunto de endereços web identificados como maliciosos, suspeitos ou indesejados.
- Utilizadas para bloquear o acesso ou alertar sobre conexões potencialmente perigosas.

### Por que adicionar listas de URL?

- **Prevenção de acesso a sites maliciosos:** Impede que usuários e sistemas acessem recursos nocivos.
- **Bloqueio de downloads de conteúdo malicioso:** Evita contaminação por arquivos baixados via web.
- **Complementação de outras camadas de proteção:** Suporta firewalls, antivírus e sistemas de e-mail na identificação de ameaças.

### Como realizar essa rotina?

1. **Obter listas de URL atualizadas:**  
   Busque feeds confiáveis e atualizados em fontes como MISP, AlienVault OTX, PhishTank, ou provedores de inteligência de ameaças.

2. **Formatar as listas para cada sistema:**  
   Adapte o formato para a plataforma de destino (firewall, antivírus, filtro de e-mail), garantindo compatibilidade.

3. **Importar as listas nos sistemas de segurança:**  
   - **Firewall:** para bloquear requisições HTTP/HTTPS a URLs maliciosas.  
   - **Antivírus/Web Proxy:** para alertas e bloqueios baseados em URLs.  
   - **Segurança de e-mail:** para bloquear links maliciosos em mensagens recebidas.

4. **Verificar a aplicação e funcionamento:**  
   Confirme que as listas foram importadas e ativadas, monitorando logs e alertas.

5. **Monitorar eficácia e falsos positivos:**  
   Avalie se bloqueios estão corretos, ajustando regras para minimizar impacto negativo.

### Benefícios:

- Redução de ataques via web, incluindo phishing e exploits drive-by.  
- Melhoria na visibilidade e controle do tráfego web malicioso.  
- Sincronização de proteção entre múltiplas camadas da infraestrutura.

---

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Adicionar lista IP ADDRESS V4/V6 em FW | AV | Email

Manter listas atualizadas de endereços IP IPv4 e IPv6 associados a atividades maliciosas é essencial para fortalecer a defesa contra ataques direcionados e tráfego suspeito.

### O que são listas de IP?

- Conjuntos de endereços IP identificados como fontes ou destinos de atividades maliciosas, como C2 (Command & Control), botnets, scanners, ou proxies maliciosos.
- Utilizadas para bloquear ou monitorar conexões de/para esses IPs em diferentes sistemas de segurança.

### Por que adicionar listas de IP?

- **Bloqueio preventivo de tráfego malicioso:** Impede comunicação com servidores comprometidos ou maliciosos.
- **Redução da superfície de ataque:** Minimiza conexões indesejadas na rede.
- **Complementação de outras camadas de defesa:** Trabalha junto a listas de URLs, arquivos e domínios suspeitos.

### Como realizar essa rotina?

1. **Obter listas atualizadas de IPs maliciosos:**  
   Utilize fontes confiáveis como MISP, AlienVault OTX, AbuseIPDB, Spamhaus, ou outros feeds de Threat Intelligence.

2. **Formatar a lista para o sistema alvo:**  
   Adeque o formato das listas para importação nos firewalls, antivírus, e filtros de e-mail.

3. **Importar as listas nas ferramentas de segurança:**  
   - **Firewall:** Crie regras para bloquear ou monitorar o tráfego desses IPs.  
   - **Antivírus:** Configure para alertar ou bloquear conexões com IPs maliciosos.  
   - **Filtros de e-mail:** Bloqueie conexões SMTP ou URLs embutidos relacionados a esses IPs.

4. **Verificar a aplicação e funcionamento:**  
   Confirme que as listas estão ativas e funcionando, monitorando alertas e logs para evidências de bloqueio.

5. **Revisar periodicamente:**  
   Atualize as listas frequentemente e monitore falsos positivos, ajustando conforme necessário para não impactar usuários legítimos.

### Benefícios:

- Mitigação eficaz de ameaças provenientes de IPs maliciosos conhecidos.  
- Melhora da postura geral de segurança da rede.  
- Integração com estratégias de defesa em profundidade.

---

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Adicionar lista EMAIL em FW | AV | Email

Incluir listas de endereços de e-mail associados a ameaças é fundamental para reforçar a proteção contra phishing, spear-phishing e outras tentativas de ataque via correio eletrônico.

### O que são listas de e-mail?

- Conjuntos de endereços de e-mail identificados como remetentes maliciosos ou comprometidos, usados para ataques, spam, phishing ou distribuição de malware.
- Utilizadas para bloquear, monitorar ou filtrar mensagens recebidas desses remetentes.

### Por que adicionar listas de e-mail?

- **Bloqueio de remetentes maliciosos:** Previne que mensagens perigosas cheguem até os usuários finais.  
- **Redução de riscos de phishing:** Impede tentativas de acesso fraudulento via e-mail.  
- **Complementação das defesas de e-mail:** Integração com filtros antispam e antivírus para reforço da segurança.

### Como realizar essa rotina?

1. **Coletar listas atualizadas de e-mails maliciosos:**  
   Utilize fontes confiáveis como MISP, AlienVault OTX, provedores de inteligência contra phishing, ou sistemas internos de coleta de IOCs.

2. **Formatar a lista para importação:**  
   Adeque os formatos para os sistemas de firewall, antivírus e plataformas de e-mail corporativo (ex: Exchange, Zimbra).

3. **Importar as listas nos sistemas de proteção:**  
   - **Firewall:** Bloqueie tráfego SMTP/POP/IMAP oriundo ou destinado a esses e-mails quando possível.  
   - **Antivírus e antispam:** Configure filtros para rejeitar ou colocar em quarentena mensagens de endereços listados.  
   - **Serviços de e-mail:** Atualize regras de transporte, bloqueio ou filtros específicos para endereços da lista.

4. **Monitorar a eficácia:**  
   Analise logs e alertas para identificar tentativas de bypass ou falsos positivos, ajustando as listas conforme necessário.

5. **Atualizar frequentemente:**  
   Mantenha a lista atualizada para acompanhar novas ameaças e evitar bloqueios desnecessários.

### Benefícios:

- Fortalecimento da segurança do ambiente de e-mail corporativo.  
- Mitigação de ataques direcionados via e-mail.  
- Melhoria na reputação e conformidade da organização.

---

## DIA x: 🔍 Rotina Diária – Gestão de Serviço de IOC: Realizar backup das bases de IOC

Manter backups atualizados das bases de Indicadores de Comprometimento (IOCs) é essencial para garantir a continuidade da operação e a integridade das informações em caso de falhas, corrupção ou ataques cibernéticos.

### Por que fazer backup das bases de IOC?

- **Proteção contra perda de dados:** Falhas de hardware, erros humanos ou ataques podem comprometer a base.  
- **Recuperação rápida:** Permite restaurar rapidamente as informações e minimizar impactos operacionais.  
- **Integridade dos dados:** Garante que os indicadores históricos e recentes estejam disponíveis para análises futuras e correlações.

### Como realizar essa rotina?

1. **Identificar todas as fontes e sistemas que armazenam IOC:**  
   Ex: MISP, AlienVault OTX, bases internas de Threat Intelligence, SIEM.

2. **Definir a frequência do backup:**  
   - Diária para ambientes dinâmicos.  
   - Ajustar conforme volume e criticidade.

3. **Automatizar o processo sempre que possível:**  
   Scripts ou ferramentas específicas para exportar e salvar as bases.

4. **Armazenar backups em local seguro e redundante:**  
   - Local diferente do ambiente principal.  
   - Preferencialmente em ambiente offline ou protegido contra alterações indevidas.

5. **Validar periodicamente os backups:**  
   Testar a restauração para garantir a integridade dos dados.

6. **Documentar o procedimento e controlar acessos:**  
   Garantir que somente pessoas autorizadas possam manipular os backups.

### Benefícios:

- Aumento da resiliência da equipe de segurança.  
- Preservação do conhecimento sobre ameaças e indicadores.  
- Suporte eficaz em resposta a incidentes.

---

## DIA x: 🐝 Rotina Diária – Implantação e Manutenção de Honeypot: Extrair indicadores dos ataques capturados

A implantação de honeypots é uma estratégia proativa para detectar e analisar atividades maliciosas que tentam explorar sua rede. Esses sistemas simulam serviços ou dispositivos vulneráveis, atraindo atacantes e coletando dados valiosos.

### Objetivo da rotina de extração de IOCs:

- Transformar os dados coletados pelo honeypot em indicadores acionáveis (IPs, domínios, hashes, payloads, técnicas) para fortalecer a defesa.

### Passos para extrair e utilizar os indicadores:

1. **Coletar os logs e alertas do honeypot:**  
   - Reúna registros de conexões, tentativas de exploração, comandos executados, arquivos transferidos e outros eventos.

2. **Analisar os dados capturados:**  
   - Identifique padrões, endereços IP de origem, domínios, URLs maliciosas e payloads usados.  
   - Utilize ferramentas de análise para decodificar e classificar ataques.

3. **Gerar IOCs relevantes:**  
   - IPs e ranges usados pelos atacantes.  
   - Domínios e URLs maliciosos.  
   - Hashes de arquivos maliciosos detectados.  
   - Assinaturas de payloads ou técnicas específicas.

4. **Validar e filtrar IOCs:**  
   - Evite falsos positivos conferindo se os indicadores não são legítimos ou conhecidos como benignos.

5. **Distribuir os IOCs para sistemas de defesa:**  
   - Importar em SIEM para correlação de eventos.  
   - Atualizar listas de bloqueio em firewalls e proxies.  
   - Enviar para antivírus e sistemas de prevenção.

6. **Registrar e documentar os indicadores extraídos:**  
   - Manter histórico para análises futuras e auditorias.

7. **Ajustar e manter o honeypot:**  
   - Atualizar configurações para capturar novas ameaças.  
   - Monitorar desempenho e disponibilidade do sistema.

### Benefícios dessa rotina:

- Aumenta a visibilidade sobre tentativas reais de ataque.  
- Fornece inteligência atualizada para defesa ativa.  
- Ajuda a antecipar e mitigar ameaças emergentes.

---

## DIA x: 🐝 Rotina Diária – Implantação e Manutenção de Honeypot: Extrair indicadores dos ataques capturados

A utilização de honeypots é uma prática valiosa para detecção e análise de ataques em ambientes controlados, permitindo coletar informações reais sobre as técnicas e origens dos agentes maliciosos. Essa rotina visa extrair indicadores de comprometimento (IOCs) dos dados capturados, para fortalecer as defesas.

### Objetivos:
- Identificar IPs, domínios e payloads utilizados pelos atacantes.
- Gerar IOCs confiáveis para alimentar o SIEM, firewalls, antivírus e outras ferramentas de segurança.
- Manter o honeypot atualizado e funcional para continuar a coleta eficiente.

### Passos recomendados:

1. **Coleta dos logs e eventos do honeypot:**  
   - Extraia logs completos de conexões, tentativas de acesso, exploits e payloads.

2. **Análise dos dados capturados:**  
   - Classifique e filtre os eventos para identificar padrões suspeitos.
   - Extraia endereços IP de origem, nomes de domínio, URLs, hashes de arquivos e códigos maliciosos.

3. **Geração dos IOCs:**  
   - Compile listas de IPs maliciosos e domínios relacionados.
   - Liste hashes e assinaturas de payloads identificados.
   - Formate os dados para integração com as ferramentas de segurança.

4. **Validação dos indicadores:**  
   - Verifique falsos positivos para evitar bloqueios indevidos.
   - Correlacione com outras fontes de inteligência para maior precisão.

5. **Distribuição dos IOCs:**  
   - Atualize regras do SIEM, firewalls e sistemas de antivírus com os indicadores extraídos.
   - Compartilhe dados com equipes de resposta a incidentes.

6. **Documentação e relatório:**  
   - Registre as atividades do honeypot, indicadores extraídos e ações tomadas.
   - Utilize para aprendizado e melhoria contínua.

7. **Manutenção do honeypot:**  
   - Atualize e ajuste a configuração para simular ambientes realistas.
   - Monitoramento constante para garantir disponibilidade.

---

## DIA x: 🐝 Rotina Diária – Implantação e Manutenção de Honeypot: Monitorar alertas e notificações

Manter o honeypot ativo e monitorado é essencial para garantir a detecção precoce de atividades maliciosas e o fornecimento contínuo de informações relevantes para a segurança da rede.

### Objetivos:
- Detectar alertas críticos e anomalias geradas pelo honeypot.
- Responder rapidamente a sinais de ataques ou tentativas de invasão.
- Garantir a integridade e disponibilidade do honeypot.

### Passos recomendados:

1. **Verificação de alertas críticos:**
   - Acesse o painel ou sistema de gerenciamento do honeypot para revisar alertas recentes.
   - Priorize alertas que indiquem tentativas de exploração, varreduras agressivas ou payloads suspeitos.

2. **Análise de notificações e logs:**
   - Examine notificações automáticas enviadas por e-mail, SMS ou sistemas integrados.
   - Revise os logs detalhados para identificar padrões incomuns ou repetições.

3. **Classificação de anomalias:**
   - Diferencie entre falsos positivos e possíveis ameaças reais.
   - Utilize inteligência contextual e histórico para avaliação precisa.

4. **Ações imediatas:**
   - Caso haja indicação de ataque ativo, notifique a equipe de segurança para investigação aprofundada.
   - Se necessário, isole ou reinicie o honeypot para preservar o ambiente.

5. **Ajuste da configuração do honeypot:**
   - Baseado nos alertas, ajuste regras e sensores para melhorar a detecção.
   - Atualize assinaturas e mecanismos de captura de dados.

6. **Documentação e comunicação:**
   - Registre os alertas recebidos, análises feitas e ações tomadas.
   - Compartilhe informações relevantes com o time de resposta a incidentes e stakeholders.

---

## DIA x: 🔍 Rotina Diária – Busca e Monitoramento de Data Leak: Validar e correlacionar dados encontrados

A exposição de dados sensíveis pode representar um sério risco à segurança da organização. Portanto, é fundamental validar e correlacionar os dados encontrados para entender sua origem e o impacto potencial.

### Objetivos:
- Confirmar a autenticidade dos dados encontrados em vazamentos.
- Identificar a abrangência e o impacto na organização.
- Agilizar ações corretivas e mitigadoras.

### Passos recomendados:

1. **Coleta dos dados vazados:**
   - Utilize fontes confiáveis e ferramentas de monitoramento de vazamentos, como plataformas de Threat Intelligence, Dark Web Monitoring e serviços de Data Leak Detection.
   - Registre os detalhes: tipo de dado, volume, origem aparente e data da exposição.

2. **Validação da propriedade dos dados:**
   - Correlacione informações como e-mails, domínios, IPs, números de documentos ou outras identificações com os dados internos da organização.
   - Utilize bases internas (ex: banco de dados de colaboradores, clientes, sistemas de RH, CRM) para confirmar se os dados realmente pertencem à empresa.

3. **Avaliação do impacto:**
   - Determine a sensibilidade dos dados (ex: dados pessoais, financeiros, segredos comerciais).
   - Estime o alcance e possível exposição (quantidade de registros, tipo de dados comprometidos).
   - Analise possíveis consequências legais, regulatórias e reputacionais.

4. **Correlacionar com eventos internos:**
   - Verifique se houve incidentes de segurança relacionados, como acessos não autorizados ou incidentes de phishing.
   - Correlacione com alertas do SIEM e logs de segurança para identificar possíveis vetores de ataque.

5. **Documentação:**
   - Registre todas as informações validadas, evidências e análises realizadas.
   - Mantenha histórico atualizado para suporte em auditorias e investigações.

6. **Notificação e resposta:**
   - Informe as áreas responsáveis (segurança, jurídico, comunicação).
   - Aplique medidas de contenção, como bloqueios, redefinição de senhas, monitoramento reforçado.
   - Inicie comunicação formal, se necessário, para clientes ou parceiros afetados.

---

## DIA x: 🔍 Rotina Diária – Busca e Monitoramento de Data Leak: Coletar dados de vazamentos

A coleta sistemática de informações sobre vazamentos de dados é essencial para antecipar riscos e proteger a organização.

### Fontes para coleta:
- **Telegram**: canais especializados que divulgam vazamentos recentes. Use bots ou scripts para monitorar e extrair dados automaticamente.
- **Sites de Data Leak**: plataformas públicas e privadas que agregam dados expostos, como Have I Been Pwned, DeHashed, LeakCheck, e fóruns específicos.
- **Dark Web**: monitoramento manual ou automatizado em fóruns, marketplaces e redes ocultas.
- **Feeds de Threat Intelligence**: serviços pagos ou gratuitos que entregam dados atualizados sobre vazamentos e ameaças.

### Procedimentos recomendados:

1. **Configurar monitoramento automatizado:**
   - Use ferramentas que realizem scraping de sites e canais confiáveis.
   - Configure alertas para novas publicações relacionadas ao setor ou à empresa.

2. **Filtrar dados relevantes:**
   - Priorize informações que contenham nomes de domínio, e-mails, IPs ou outros identificadores ligados à empresa.
   - Evite ruído e falsos positivos, focando em dados úteis para investigação.

3. **Armazenar dados de forma segura:**
   - Utilize bancos de dados protegidos para guardar registros coletados.
   - Mantenha controle de acesso rigoroso para evitar exposição dos dados sensíveis.

4. **Atualizar a equipe e sistemas:**
   - Compartilhe dados com o time de segurança e analistas para análise e ação.
   - Alimente sistemas de defesa como SIEM, firewalls, antivírus e PAM com os indicadores coletados.

---

## DIA x: [RACI] Senhas Fracas ou Padrão

**Risco:** Utilização de senhas fracas, padrão (como "admin123") ou facilmente adivinháveis para contas de sistemas críticos.

### Ação recomendada:
- Fazer um **dump das senhas do Active Directory (AD)** utilizando ferramentas seguras e autorizadas (ex: Mimikatz, Hashdump).
- Realizar um **teste de força bruta baseado em hashes** para identificar senhas populares, padrões e vulneráveis.
- Validar a existência de senhas fracas e catalogar os usuários que as utilizam.

### Objetivo:
- Detectar contas que apresentam risco devido a senhas fracas.
- Promover a obrigatoriedade de troca imediata dessas senhas.
- Fortalecer políticas de senha e implementar mecanismos adicionais como MFA (Autenticação Multifator).

### Observações:
- Esse processo deve ser conduzido com autorização da gestão de segurança e de forma ética.
- Os dados coletados devem ser tratados com confidencialidade para evitar exposição indevida.
- Idealmente, automatizar essa análise periodicamente para mitigar riscos continuamente.

---

**Responsável:** Equipe de Segurança da Informação (SOC)  
**Apoiador:** Administradores de AD, Infraestrutura  
**Consultado:** Auditoria e Compliance  
**Informado:** Gestão Executiva

## DIA x: [RACI] Ausência de Revisão Periódica de Permissões

**Risco:**  
Permissões de acesso não são revisadas regularmente, permitindo que usuários mantenham acessos desnecessários a sistemas críticos, aumentando o risco de abuso ou comprometimento.  

---

### Contexto:  
Foco na revisão de permissões a nível de aplicações, onde o controle granular nem sempre é automatizado, o que pode gerar riscos significativos de privilégio excessivo.

---

### Ação Recomendada:  
- Implementar uma rotina periódica (mensal ou trimestral) para revisão das permissões em sistemas e aplicações críticas.  
- Utilizar relatórios detalhados que listem usuários, suas permissões e o uso efetivo dessas permissões.  
- Validar com os responsáveis pelos sistemas e gestores se os acessos concedidos são necessários e adequados.  
- Revogar imediatamente acessos obsoletos ou excessivos.  
- Documentar o processo e os resultados das revisões para auditoria.  

---

### Objetivo:  
- Minimizar riscos de exposição e abuso de permissões.  
- Assegurar que o princípio do menor privilégio seja respeitado.  
- Fortalecer a governança e compliance de segurança.  

---

### Boas Práticas:  
- Integrar essa revisão com sistemas de gestão de identidade e acesso (IAM) sempre que possível.  
- Automatizar alertas para permissões inativas ou não utilizadas.  
- Sensibilizar gestores e usuários sobre a importância do controle de acesso.  

---

### Responsabilidades (RACI):

| Papel               | Responsabilidade                                         |
|---------------------|---------------------------------------------------------|
| **Responsável (R)** | Equipe de Segurança da Informação / IAM                 |
| **Apoiador (A)**    | Administradores de Sistemas, Gestores de Aplicação      |
| **Consultado (C)**  | Auditoria, Compliance, Usuários-chave                    |
| **Informado (I)**   | Gestão Executiva, Área Jurídica                           |

---

## DIA x: [RVSA] Configurações Padrão ou Inseguras em Servidores e Aplicações

**Risco:**  
Sistemas operam com configurações padrão que não são otimizadas para segurança, como credenciais padrão, permissões excessivas ou serviços desnecessários habilitados, tornando-os vulneráveis a ataques.

---

### Ação Recomendada:  
- Realizar um scan completo nos servidores e aplicações para identificar credenciais padrão, senhas fracas ou ausentes, e configurações inseguras.  
- Utilizar ferramentas de Threat Intelligence para identificar vulnerabilidades conhecidas e padrões inseguros.  
- Verificar permissões excessivas e desabilitar serviços não essenciais.  
- Atualizar configurações seguindo as melhores práticas e hardening recomendados para cada sistema.  
- Documentar as alterações e manter registros para auditoria.

---

### Objetivo:  
- Reduzir a superfície de ataque eliminando configurações inseguras e padrões vulneráveis.  
- Fortalecer a postura de segurança da infraestrutura e aplicações.

---

### Boas Práticas:  
- Implementar políticas para desabilitar ou alterar credenciais padrão durante a implantação.  
- Automatizar a varredura periódica de configurações para garantir conformidade contínua.  
- Sensibilizar equipes de infraestrutura e desenvolvimento para a importância do hardening.  

---

### Responsabilidades (RACI):

| Papel               | Responsabilidade                                           |
|---------------------|-----------------------------------------------------------|
| **Responsável (R)** | Equipe de Segurança da Informação / Infraestrutura        |
| **Apoiador (A)**    | Administradores de Sistemas, Desenvolvedores              |
| **Consultado (C)**  | Auditoria, Compliance                                      |
| **Informado (I)**   | Gestão Executiva, Área de Operações                        |

		

## DIA x: [RRC] Senhas Fracas em Dispositivos de Rede

**Risco:**  
Dispositivos de rede (como roteadores, switches, firewalls) que continuam utilizando senhas padrão ou senhas fracas, facilitando o acesso não autorizado e comprometimento da infraestrutura de rede.

---

### Ação Recomendada:  
- Realizar um levantamento completo dos dispositivos de rede em uso.  
- Executar scans utilizando ferramentas específicas para identificar credenciais padrão ou senhas fracas.  
- Utilizar bases de Threat Intelligence para validar se senhas padrão conhecidas estão em uso.  
- Alterar imediatamente todas as senhas padrão para senhas fortes e únicas, aplicando políticas de complexidade.  
- Implementar autenticação multifator (MFA) para acesso administrativo, quando possível.  
- Documentar as alterações e manter um controle rígido das credenciais.

---

### Objetivo:  
- Mitigar o risco de acesso não autorizado a dispositivos críticos da rede.  
- Garantir a integridade e disponibilidade da infraestrutura de rede.

---

### Boas Práticas:  
- Automatizar a auditoria periódica de senhas em dispositivos de rede.  
- Treinar a equipe de administração para seguir políticas rigorosas de gestão de senhas.  
- Manter um inventário atualizado dos dispositivos e suas configurações de segurança.

---

### Responsabilidades (RACI):

| Papel               | Responsabilidade                                           |
|---------------------|-----------------------------------------------------------|
| **Responsável (R)** | Equipe de Redes / Segurança da Informação                  |
| **Apoiador (A)**    | Administradores de Rede, Operações                          |
| **Consultado (C)**  | Auditoria, Compliance                                      |
| **Informado (I)**   | Gestão Executiva, Área de Infraestrutura                    |

---

## DIA x: [RRC] Exposição de Serviços Não Necessários

**Risco:**  
Serviços desnecessários e portas abertas em servidores e dispositivos, que podem ser explorados por atacantes para obter acesso não autorizado, comprometer sistemas ou realizar ataques laterais.

---

### Ação Recomendada:  
- Realizar varreduras regulares na rede para identificar portas abertas e serviços ativos (ex: Nmap, Masscan).  
- Avaliar criticamente cada serviço encontrado para determinar sua necessidade e função.  
- Desabilitar ou remover serviços e usuários padrão que não sejam essenciais para o funcionamento do ambiente.  
- Revisar políticas de firewall para bloquear portas desnecessárias.  
- Monitorar logs para detectar tentativas de conexão a serviços não autorizados.

---

### Objetivo:  
- Minimizar a superfície de ataque, reduzindo os pontos vulneráveis expostos na rede.  
- Garantir que somente serviços essenciais estejam ativos e expostos conforme a necessidade operacional.

---

### Boas Práticas:  
- Automatizar scans de portas e serviços periodicamente.  
- Implementar gestão de configuração e hardening de servidores.  
- Manter um inventário atualizado dos serviços ativos e suas justificativas.  
- Treinar equipes para identificar e responder rapidamente a exposições indevidas.

---

### Responsabilidades (RACI):

| Papel               | Responsabilidade                                           |
|---------------------|-----------------------------------------------------------|
| **Responsável (R)** | Equipe de Redes / Segurança da Informação                  |
| **Apoiador (A)**    | Administradores de Sistemas e Redes                         |
| **Consultado (C)**  | Auditoria, Compliance                                      |
| **Informado (I)**   | Gestão Executiva, Área de Infraestrutura                    |

---

## DIA x: 🔍 Auditoria de Credenciais em Servidores com Pastas Compartilhadas

### Objetivo  
Identificar e listar credenciais que estejam armazenadas em servidores, especialmente em pastas compartilhadas, para evitar vazamentos e acessos indevidos.

### Riscos  
- Credenciais armazenadas em locais acessíveis facilitam o movimento lateral por atacantes.  
- Possibilidade de comprometimento de múltiplos sistemas através do uso de credenciais expostas.  
- Falta de controle sobre quem tem acesso às credenciais compartilhadas.

### Ações recomendadas  
- Realizar varredura nos servidores para localizar arquivos contendo senhas, tokens, ou chaves.  
- Revisar permissões de pastas compartilhadas para garantir acesso restrito.  
- Utilizar ferramentas para inventariar e analisar arquivos com credenciais sensíveis.  
- Promover a utilização de cofres de senha (Password Vaults) para armazenamento seguro.  
- Eliminar arquivos desnecessários contendo credenciais.  

---

## DIA x: Auditoria de Routers Mikrotik sem senha configurada

### Objetivo
Identificar roteadores Mikrotik na rede que estejam sem senha ou utilizando credenciais padrão, mitigando riscos de acesso não autorizado.

### Riscos
- Acesso indevido à rede por dispositivos desprotegidos.
- Possibilidade de invasões, alteração de configurações e criação de backdoors.
- Comprometimento da infraestrutura de rede e dos dados trafegados.

### Passos para verificação

1. **Mapear a rede para identificar dispositivos Mikrotik ativos**
   - Use ferramentas como `nmap` para descobrir IPs e portas abertas típicas do Mikrotik (ex: Winbox na porta 8291).
   - Exemplo de comando:
     ```bash
     nmap -p 8291 --open -sV 192.168.0.0/24
     ```
2. **Testar acesso com credenciais padrão**
   - Tentar login via Winbox, SSH ou interface web com usuário "admin" e senha em branco.
3. **Listar dispositivos com acesso vulnerável**
   - Documentar IP, modelo, e status de segurança.
4. **Corrigir configurações de segurança**
   - Configurar senhas fortes para todas as interfaces.
   - Habilitar autenticação multifator, se disponível.
   - Atualizar firmware para a versão mais recente.
5. **Monitorar periodicamente**
   - Realizar auditorias regulares para garantir que novos dispositivos não fiquem desprotegidos.

### Ferramentas recomendadas
- **Nmap** para scan de rede.
- **Winbox** para gerenciamento Mikrot

---

## DIA x: Planejamento e Execução de Campanha de Phishing Simulado

### Objetivo
Realizar uma campanha de phishing controlada para conscientizar colaboradores, testar a resiliência da equipe e identificar vulnerabilidades no processo de segurança.

### Etapas da Campanha

1. **Definir escopo e público-alvo**
   - Escolher grupos ou setores da empresa para a campanha.
   - Obter aprovações da liderança e do setor jurídico.

2. **Criar cenário realista e convincente**
   - Desenvolver e-mails e páginas falsas que simulem ataques reais (ex: falsa solicitação de senha, atualização de sistema).
   - Usar linguagem e design coerentes com o ambiente corporativo.

3. **Planejar mecanismos de rastreamento**
   - Configurar ferramentas para monitorar cliques, envio de credenciais, respostas.
   - Garantir anonimato e privacidade dos participantes.

4. **Executar a campanha**
   - Enviar os e-mails simulados conforme o cronograma.
   - Monitorar em tempo real as interações dos usuários.

5. **Analisar resultados**
   - Identificar número de cliques, envios de dados, desistências.
   - Avaliar padrões e perfis de maior risco.

6. **Feedback e treinamento**
   - Compartilhar os resultados com os participantes.
   - Fornecer treinamentos e materiais para melhorar a conscientização.

7. **Ajustar políticas e controles**
   - Implementar melhorias baseadas nas falhas identificadas.
   - Reforçar controles técnicos e administrativos.

### Considerações Importantes
- Nunca usar dados reais coletados para fins maliciosos.
- Manter comunicação clara com liderança e áreas envolvidas.
- Realizar campanhas periódicas para fortalecer a cultura de segurança.

---

## DIA x: Teste de Exploração e Movimento Lateral na Rede de Servidores

### Objetivo
Avaliar a segurança da rede interna, identificando possíveis vulnerabilidades que permitam a exploração inicial e o movimento lateral entre servidores.

### Etapas do Teste

1. **Planejamento**
   - Definir o escopo do teste: servidores e segmentos de rede autorizados.
   - Obter autorização formal da liderança e equipes envolvidas.
   - Preparar ferramentas e scripts para exploração e movimentação lateral.

2. **Reconhecimento Interno**
   - Mapear ativos, portas abertas, serviços ativos.
   - Identificar credenciais armazenadas ou expostas.
   - Levantar políticas de acesso e segmentação.

3. **Exploração Inicial**
   - Testar vulnerabilidades conhecidas nos sistemas operacionais e aplicações.
   - Realizar ataques controlados (ex: exploits, phishing interno).
   - Obter acesso inicial a pelo menos um servidor.

4. **Movimento Lateral**
   - Utilizar credenciais obtidas para acessar outros servidores.
   - Explorar serviços de rede (RDP, SMB, SSH) para escalonamento.
   - Avaliar mecanismos de detecção e bloqueio de movimentos laterais.

5. **Escalonamento de Privilégios**
   - Buscar elevação de privilégios para acesso administrativo.
   - Testar credenciais padrão ou fracas nos servidores.

6. **Documentação e Relatório**
   - Registrar passos realizados, vulnerabilidades encontradas e recomendações.
   - Avaliar impacto potencial e riscos envolvidos.
   - Apresentar relatório para equipe de segurança e gestão.

### Considerações de Segurança
- Realizar testes fora do horário comercial para minimizar impacto.
- Garantir backup e plano de recuperação antes do início.
- Respeitar as normas internas e leis vigentes.

---

## DIA x: [RACI] Falta de Controle de Acesso a Sistemas de Gestão

### Risco
Contas com permissões administrativas em sistemas críticos de gestão (ERP, CRM, etc.) são distribuídas sem critérios rigorosos, aumentando a superfície de ataque e o risco de acessos indevidos ou mal-intencionados.

### Objetivo
Garantir que o acesso administrativo aos sistemas de gestão seja restrito, controlado e auditado conforme as políticas de segurança da empresa.

### Ações Recomendas

- **Mapear** todas as contas com privilégios administrativos nos sistemas de gestão.
- **Validar** se os acessos são compatíveis com as responsabilidades e funções dos usuários.
- **Implementar** controle de acesso baseado no princípio do menor privilégio (least privilege).
- **Realizar** revisões periódicas das permissões concedidas.
- **Auditar** logs de acesso e alterações feitas por usuários administrativos.
- **Configurar** autenticação multifator (MFA) para contas administrativas.
- **Documentar** processos e responsáveis pelo controle de acesso.
- **Treinar** usuários e administradores sobre boas práticas de segurança e riscos associados.

### Responsabilidades

| Atividade                             | Responsável          | Aprovador           | Consultado          | Informado           |
|-------------------------------------|---------------------|---------------------|---------------------|---------------------|
| Mapear contas administrativas       | Equipe de TI        | Segurança da Informação | Gestores dos sistemas | Usuários finais      |
| Revisão periódica de permissões     | Segurança da Informação | Compliance          | TI e gestores       | Auditoria            |
| Implementar MFA                     | Equipe de TI        | Segurança da Informação | Gestores de TI      | Usuários             |
| Auditoria de acessos                | Auditoria interna   | Gestão Executiva    | Segurança da Informação | Usuários             |

---

## DIA x: [RRC] Falta de Segmentação de Rede

### Risco
A ausência de segmentação adequada na rede interna permite que dispositivos e usuários tenham comunicação irrestrita entre si, aumentando o risco de movimentação lateral em caso de comprometimento e facilitando a propagação de ataques.

### Objetivo
Implementar e manter uma segmentação eficaz da rede para limitar o acesso e reduzir a superfície de ataque, controlando e monitorando o tráfego entre segmentos.

### Ações Recomendadas

- **Mapear** a topologia atual da rede e identificar ativos críticos.
- **Definir** zonas de segurança (ex: segmentação por departamentos, funções, níveis de confiança).
- **Configurar** VLANs e regras de firewall para controlar o tráfego entre segmentos.
- **Aplicar** políticas de acesso baseadas no princípio do menor privilégio.
- **Monitorar** continuamente o tráfego entre segmentos para detectar anomalias.
- **Realizar** testes de penetração para validar a eficácia da segmentação.
- **Documentar** a arquitetura e políticas de segmentação.
- **Treinar** equipe de rede e segurança sobre práticas e importância da segmentação.

### Responsabilidades

| Atividade                          | Responsável        | Aprovador           | Consultado          | Informado           |
|----------------------------------|--------------------|---------------------|---------------------|---------------------|
| Mapeamento e análise da rede     | Equipe de Rede     | Segurança da Informação | Gestão de TI        | Usuários            |
| Configuração de VLANs e firewalls| Equipe de Rede     | Segurança da Informação | Gestão de TI        | Usuários            |
| Monitoramento de tráfego         | Equipe de Segurança| Gestão de Segurança  | Equipe de Rede      | Gestão Executiva     |
| Testes de penetração             | Equipe de Segurança| Gestão Executiva    | TI e Rede           | Auditoria            |

---

## DIA x: [RGDC] Falta de Treinamento sobre Proteção de Dados

### Risco
Colaboradores sem treinamento adequado em segurança da informação podem causar incidentes por falhas humanas, exposição acidental de dados sensíveis ou abertura para ataques de engenharia social.

### Objetivo
Garantir que todos os colaboradores estejam capacitados sobre as melhores práticas de proteção de dados, políticas internas e procedimentos para minimizar riscos de segurança.

### Ações Recomendadas

- **Mapear** o público-alvo para treinamentos (novos colaboradores, times críticos, gestores).
- **Desenvolver** um programa de treinamento contínuo sobre proteção de dados, privacidade e segurança da informação.
- **Aplicar** treinamentos regulares (online e presenciais) com conteúdos atualizados e práticos.
- **Realizar** campanhas de conscientização periódicas (e-mails, cartazes, vídeos).
- **Simular** ataques de phishing para reforçar a atenção dos colaboradores.
- **Avaliar** a eficácia dos treinamentos através de testes e feedbacks.
- **Atualizar** políticas internas e disponibilizar manuais acessíveis.
- **Registrar** participação e progresso dos colaboradores.
- **Incluir** tópicos específicos de LGPD e outras legislações aplicáveis.

### Responsabilidades

| Atividade                     | Responsável          | Aprovador             | Consultado            | Informado            |
|-------------------------------|---------------------|-----------------------|-----------------------|----------------------|
| Desenvolvimento do programa   | Equipe de Segurança | Gestão de RH          | Jurídico              | Colaboradores        |
| Aplicação dos treinamentos    | Equipe de RH        | Gestão de Segurança   | Equipe de Segurança   | Colaboradores        |
| Campanhas de conscientização  | Comunicação Interna | Gestão Executiva      | Equipe de Segurança   | Toda a organização   |
| Avaliação e feedback          | Equipe de Segurança | Gestão de RH          | Gestão Executiva      | Colaboradores        |

---

## DIA x: [RCNPD] Falta de Treinamento e Simulações

### Risco
Colaboradores despreparados para situações de continuidade de negócios e recuperação de desastres podem aumentar o tempo de inatividade, perdas financeiras e impacto negativo na reputação da empresa.

### Objetivo
Garantir que todos os envolvidos conheçam os procedimentos de continuidade e recuperação, saibam agir em situações de crise e minimizem os impactos causados por incidentes.

### Ações Recomendadas

- **Mapear** os colaboradores-chave envolvidos no plano de continuidade e recuperação.
- **Desenvolver** treinamentos específicos sobre políticas, processos e responsabilidades em continuidade de negócios (BCP) e recuperação de desastres (DRP).
- **Realizar** simulações periódicas (tabletop exercises, testes práticos) para validar o plano e o desempenho da equipe.
- **Atualizar** e documentar o plano com base nas lições aprendidas durante os treinamentos e testes.
- **Comunicar** a importância do treinamento e das simulações para toda a organização.
- **Registrar** a participação e os resultados das simulações para auditoria e melhoria contínua.

### Responsabilidades

| Atividade                       | Responsável            | Aprovador            | Consultado           | Informado            |
|---------------------------------|-----------------------|----------------------|----------------------|----------------------|
| Desenvolvimento de treinamentos | Equipe de Segurança   | Gestão de TI         | Gestão de Riscos     | Colaboradores-chave  |
| Execução de simulações           | Equipe de Segurança   | Gestão de TI         | Gestão Executiva     | Toda a organização   |
| Atualização do plano             | Gestão de TI          | Gestão de Riscos     | Equipe de Segurança  | Colaboradores-chave  |

---

## DIA x: [RACI] Compartilhamento de Contas entre Usuários

### Risco
O compartilhamento de contas entre múltiplos usuários dificulta a rastreabilidade das ações realizadas no ambiente, comprometendo auditorias, investigações e controles de segurança.

### Objetivo
Detectar e mitigar o uso compartilhado de contas para garantir a responsabilização individual e aumentar a segurança no ambiente corporativo.

### Ações Recomendadas

- **Configurar regras no SIEM** para monitorar eventos de autenticação suspeitos, como múltiplos logins simultâneos ou sucessivos a partir de diferentes localidades ou dispositivos com a mesma conta.
- **Integrar múltiplas fontes de logs** no SIEM, incluindo:
  - Logs de autenticação do Active Directory (AD)
  - Logs do ClearClock (se aplicável)
  - Logs de sistemas de VPN, proxies, firewalls e aplicações críticas
- **Gerar alertas automáticos** para detecção de comportamentos anômalos relacionados ao uso compartilhado de contas.
- **Realizar análises periódicas** para identificar padrões de compartilhamento, como acessos em horários conflitantes ou dispositivos desconhecidos.
- **Promover políticas claras** de uso individual de contas, com comunicação e treinamento para os usuários.
- **Implementar autenticação multifator (MFA)** para fortalecer a autenticação e desencorajar o compartilhamento.
- **Revisar e desabilitar contas compartilhadas**, criando contas individuais sempre que possível.
- **Documentar incidentes e medidas corretivas** para auditoria e melhorias futuras.

### Responsabilidades

| Atividade                               | Responsável           | Aprovador            | Consultado           | Informado            |
|----------------------------------------|----------------------|----------------------|----------------------|----------------------|
| Configuração e manutenção das regras   | Equipe de Segurança  | Gestão de TI         | Administradores AD   | Usuários             |
| Análise e investigação de alertas      | Analistas SOC        | Gestão de Segurança  | TI e RH              | Gestão Executiva     |
| Comunicação e treinamento de usuários  | RH / Comunicação     | Gestão de Segurança  | Equipe de Segurança  | Todos colaboradores  |

---

## DIA x: [RACI] Política de Senhas Inadequada

### Risco
Políticas de senha fracas ou mal configuradas permitem o uso de senhas simples, repetidas ou reaproveitamento de senhas antigas, facilitando ataques de força bruta, adivinhação e comprometimento de contas.

### Objetivo
Implementar uma política de senhas robusta que imponha regras rigorosas para criação, alteração e validade das senhas, aumentando a segurança do ambiente.

### Ações Recomendadas

- **Definir requisitos mínimos para senhas**:
  - Comprimento mínimo (ex: 12 caracteres)
  - Uso obrigatório de caracteres maiúsculos, minúsculos, números e símbolos
  - Proibir senhas comuns, padrões ou óbvias (ex: "123456", "password")
  - Evitar repetições e sequências
- **Implementar histórico de senhas** para impedir reutilização de senhas antigas.
- **Forçar alteração periódica de senhas**, mas evitando trocas muito frequentes que causem fadiga e escolha de senhas fracas.
- **Aplicar bloqueio após tentativas falhas** para impedir ataques automatizados.
- **Utilizar ferramentas de verificação de senhas** contra listas de senhas comprometidas (ex: Have I Been Pwned).
- **Treinar usuários** sobre boas práticas de criação e uso de senhas.
- **Implementar autenticação multifator (MFA)** para aumentar a segurança, mesmo que a senha seja comprometida.
- **Auditar periodicamente a conformidade** da política de senhas nos sistemas críticos.

### Responsabilidades

| Atividade                                  | Responsável          | Aprovador           | Consultado          | Informado            |
|-------------------------------------------|---------------------|---------------------|---------------------|----------------------|
| Definição e atualização da política       | Equipe de Segurança  | Gestão de TI        | RH, Jurídico        | Todos colaboradores  |
| Implementação técnica                      | Administradores TI  | Gestão de TI        | Segurança           | Usuários             |
| Monitoramento e auditoria                  | Analistas SOC       | Gestão de Segurança | TI, Auditoria       | Gestão Executiva     |
| Treinamento e comunicação                  | RH / Comunicação    | Gestão de Segurança | Segurança           | Todos colaboradores  |

---
		
## DIA x: [RRC] Exposição de Serviços Não Necessários

### Risco  
Serviços desnecessários e portas abertas em servidores aumentam a superfície de ataque, expondo a rede a riscos de invasão e exploração.

### Objetivo  
Realizar uma limpeza e restrição dos serviços e portas em servidores de produção para reduzir os vetores de ataque, alinhado à recomendação do Josimar.

### Ações Recomendadas

- Mapear todos os serviços ativos e portas abertas nos servidores em produção.
- Identificar quais serviços são essenciais para a operação e quais podem ser desativados.
- Fechar portas e desabilitar serviços desnecessários.
- Aplicar controles de acesso, permitindo conexões apenas de IPs e redes confiáveis.
- Documentar as alterações realizadas para auditoria e futuras manutenções.
- Realizar varreduras periódicas para garantir que não haja reabertura indevida de portas.

### Ferramentas para auxílio

- `nmap` (```nmap -sV -p- <IP_DO_SERVIDOR>```) para listar portas abertas e versões dos serviços.
- Comandos locais como `netstat`, `ss`, `lsof` para identificar processos e portas em uso.
- Firewalls e listas de controle de acesso (iptables, firewalld, ACLs de roteadores).

### Exemplos de portas comuns para revisão

- Telnet (23)
- FTP (21)
- SMBv1 (139/445)
- RDP (3389)
- Serviços web não essenciais (80, 8080, 443)

### Responsabilidades

| Atividade                         | Responsável            | Aprovador          | Consultado         | Informado          |
|----------------------------------|-----------------------|--------------------|--------------------|--------------------|
| Levantamento de serviços          | Equipe de Infraestrutura | Gestão de TI      | Segurança da Informação | Usuários afetados   |
| Desabilitação de serviços         | Administradores de Servidores | Gestão Infraestrutura | Segurança         | Gestão Executiva    |
| Monitoramento e auditoria         | Equipe SOC            | Gestão de Segurança | Infraestrutura     | Gestão Executiva    |

---
		
## DIA x: [RRC] Ataques de Spoofing e Interceptação de Pacotes

### Risco  
Redes sem proteção contra spoofing de IP ou ARP ficam vulneráveis a ataques de interceptação, podendo permitir invasores capturarem, modificarem ou redirecionarem tráfego de rede, comprometendo a confidencialidade e integridade dos dados.

### Objetivo  
Detectar e mitigar tentativas de spoofing na rede, protegendo os ativos contra ataques de interceptação.

### Ações Recomendadas

- Implantar scripts automatizados para monitorar e detectar pacotes com endereços IP ou MAC falsificados.
- Integrar a detecção com sistemas de monitoramento e alerta (SIEM, NMS).
- Realizar bloqueio automático ou manual dos dispositivos suspeitos.
- Implementar técnicas de proteção como DHCP snooping, IP Source Guard, Dynamic ARP Inspection em switches gerenciáveis.
- Configurar segmentação adequada da rede para minimizar o impacto.

### Exemplo de script básico para detecção de ARP spoofing (Linux)

```bash
#!/bin/bash
# Script simples para detectar ARP spoofing usando arpspoof tool

arpwatch -f /var/log/arpwatch.log &

tail -f /var/log/arpwatch.log | while read line; do
  echo "$line" | grep "changed ethernet address" && \
  echo "[ALERTA] Possível ARP spoofing detectado: $line" | mail -s "Alerta ARP Spoofing" admin@empresa.com
done
```

### Ferramentas úteis

- arpwatch
- arpspoof (dsniff suite)
- tcpdump (para análise manual)
- Ferramentas integradas no switch para DHCP snooping e ARP inspection

### Responsabilidades

| Atividade                          | Responsável           | Aprovador          | Consultado           | Informado          |
|-----------------------------------|----------------------|--------------------|----------------------|--------------------|
| Implantação de script de detecção | Equipe de Segurança   | Gestão de Infraestrutura | Equipe de Redes      | Gestão Executiva    |
| Monitoramento contínuo             | SOC                  | Gestão de Segurança | Equipe de Infraestrutura | Gestão Executiva  |
| Ações de mitigação                 | Equipe de Redes       | Gestão de Infraestrutura | Equipe de Segurança  | Gestão Executiva    |

**Importante:**  
Além da detecção, a prevenção ativa com configurações de rede é fundamental para evitar ataques bem-sucedidos de spoofing.
---	
		
## DIA x: Perfis & Sessões de Usuários em Desuso

### Risco  
Perfis e sessões de usuários que não são utilizados por longos períodos representam uma vulnerabilidade, pois podem ser explorados por invasores para acesso não autorizado. Além disso, usuários inativos podem manter permissões desnecessárias, aumentando a superfície de ataque.

### Objetivo  
Identificar e remover perfis e sessões de usuários em desuso para reduzir riscos de segurança e garantir a conformidade com políticas internas.

### Ações Recomendadas

- Realizar auditoria periódica dos usuários ativos no sistema e no domínio.
- Identificar contas sem login ou atividade nos últimos 30, 60 ou 90 dias, conforme política da empresa.
- Desativar ou bloquear imediatamente contas em desuso, após validação com o gestor responsável.
- Documentar o processo de remoção ou desativação.
- Configurar alertas automáticos para detectar logins em contas consideradas inativas.
- Revisar permissões associadas às contas para evitar acessos desnecessários.

### Exemplo de comando para listar usuários inativos no Active Directory (PowerShell)

```powershell
Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly | Select-Object Name, LastLogonDate
```

### Ferramentas úteis

- PowerShell (Active Directory)
- Scripts de automação para auditoria de contas
- Ferramentas de gestão de identidade e acesso (IAM)
- SIEM para monitoramento de acessos suspeitos

### Responsabilidades

| Atividade                        | Responsável          | Aprovador          | Consultado           | Informado          |
|---------------------------------|---------------------|--------------------|----------------------|--------------------|
| Auditoria de contas inativas     | Equipe de Segurança  | Gestão de TI       | RH, Gestores de Área | Gestão Executiva   |
| Desativação ou remoção de contas | Equipe de TI        | Gestão de TI       | Equipe de Segurança  | Gestão Executiva   |
| Monitoramento contínuo           | SOC                 | Gestão de Segurança| Equipe de TI         | Gestão Executiva   |

**Importante:**  
Manter uma rotina periódica de revisão de contas e sessões é essencial para manter a segurança e reduzir riscos internos.
---

	




