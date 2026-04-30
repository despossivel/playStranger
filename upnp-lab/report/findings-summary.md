# Findings Summary — UPnP Lab

**Data:** 2026-04-24  
**Pesquisador:** Matheus Brito (@despossivel)  
**Escopo:** Rede doméstica 192.168.1.0/24 — dispositivos de propriedade do pesquisador

---

## Tabela de Findings

| # | Título | Host | CVE | CWE | CVSS | Status |
|---|---|---|---|---|---|---|
| F-01 | PlayStranger (Logical Authorization Bypass) | 192.168.1.29 | Sem CVE associado (submissao independente ao MSRC) | CWE-306, CWE-918 | 7.5 HIGH | **CONFIRMADO** |
| F-02 | UPnP Information Disclosure — GetProtocolInfo sem autenticação | 192.168.1.29 | Sem CVE associado | CWE-200, CWE-306 | 5.3 MEDIUM | **CONFIRMADO** |
| F-03 | UPnP Information Disclosure — Device Descriptor público | 192.168.1.29 | — | CWE-200 | 5.3 MEDIUM | **CONFIRMADO** |
| F-04 | RenderingControl SetVolume sem autenticação (Hardware Control) | 192.168.1.29 | Sem CVE associado | CWE-306 | 6.5 MEDIUM | **CONFIRMADO** |
| F-05 | IGD UPnP exposto no roteador | 192.168.1.1 | — | CWE-306 | A verificar | NÃO TESTADO |

---

## Detalhamento dos Findings Confirmados

### F-01 — PlayStranger (CRÍTICO para privacidade/controle)

- **Mecanismo:** `SetAVTransportURI` + `Play` sem autenticação → NSPlayer faz GET para host controlado
- **Evidência:** `User-Agent: NSPlayer/12.00.26100.7813 WMFSDK/12.00.26100.7813` capturado em callback
- **Efeito observado:** App Escape — Films & TV aberto interrompendo sessão do usuário
- **Enquadramento:** Bypass de autorizacao sem autenticacao (CWE-306) com impacto direto em UI/foreground
- **Status de identificação:** finding independente sem CVE associado no momento, recomendado para submissão dedicada ao MSRC

#### Validação de Comportamento (build atual)

**Comportamento confirmado na build 10.0.26100.7815:**

| Cenário | Comportamento | Callback recebido |
|---|---|---|
| Movies & TV instalado | NSPlayer abre e tenta reproduzir | Sim |
| Movies & TV removido | Redireciona para Microsoft Store | Sim — sessão interrompida e callback ocorre |

Os dois cenários confirmam o vetor: o callback HTTP acontece independentemente do app estar instalado. A diferença está no comportamento do player após o request.

**Implicação de segurança:** o vetor funciona em Xbox Series S out-of-the-box (Movies & TV pré-instalado por padrão). A remoção do app não mitiga completamente, pois o callback ainda ocorre antes do redirecionamento para a Store.

**Dados finais de validação:**

| Campo | Valor |
|---|---|
| Dispositivo | Xbox Series S |
| Serial | 010364220117 |
| OS Version | 10.0.26100.7815 |
| Build | xb_flt_2604ge.260414-2200 |
| Shell | 2604.0.2604.14002 |
| Confirmado | Sim — callback capturado na build atual |
| App Movies & TV | Necessário para reprodução completa; ausência não mitiga, pois o callback ocorre mesmo assim |

#### Contexto Comparativo (vetor similar, alvo distinto)

Vetor similar documentado em **CVE-2025-55971** (TCL Smart TV), com comportamento classificado como blind SSRF. No entanto, o PlayStranger em Xbox Series S apresenta diferenças técnicas relevantes que sustentam tratamento independente:

- **Stack:** Windows WMFSDK (`NSPlayer/WMFSDK`) vs Android TV
- **Porta de serviço:** 2869 (Xbox) vs 16398 (TCL)
- **Impacto:** non-blind, com captura completa de headers HTTP no callback
- **Firmware disclosure:** `NSPlayer/12.00.26100.7813` confirmado em evidência

### F-02 — GetProtocolInfo Information Disclosure

- **Mecanismo:** SOAP `GetProtocolInfo` sem autenticação retorna 200+ MIME types e perfis DLNA
- **Evidência:** Arquivo `GetProtocolInfo.xml` com sink list completo
- **Dado sensível:** Expõe surface de parsing exata, incluindo handlers PlayTo internos

### F-03 — Device Descriptor público

- **Mecanismo:** HTTP GET no endpoint `?content=uuid:...` sem autenticação
- **Dado sensível:** Hardware ID (`VEN_0125&DEV_0002`), Container ID, UDN, firmware stack

### F-04 — Hardware Control (SetVolume)

- **Mecanismo:** `RenderingControl:1#SetVolume` aceito sem autenticação
- **Efeito:** Controle do volume do hardware sem interação do usuário

---

## Referências

| Ref | Descrição |
|---|---|
| Sem CVE associado | PlayStranger tratado como finding independente para submissão ao MSRC |
| CVE-2025-55971 | Vetor similar publicado para TCL Smart TV (blind SSRF), usado apenas como contexto comparativo |
| CWE-306 | Missing Authentication for Critical Function |
| CWE-918 | Server-Side Request Forgery |
| CWE-200 | Exposure of Sensitive Information |
| OWASP A10:2021 | Server-Side Request Forgery |

---

## Recomendações de Mitigação

| Medida | Impacto | Complexidade |
|---|---|---|
| Isolar Xbox em VLAN dedicada separada de hosts não confiáveis | Alto | Baixa |
| Bloquear porta TCP/2869 no firewall para hosts não autorizados | Alto | Baixa |
| Desabilitar UPnP no roteador se não utilizado | Alto | Baixa |
| Microsoft: adicionar autenticação no AVTransport e RenderingControl | Alto | Alta |
| Microsoft: validar e restringir URIs aceitas em SetAVTransportURI | Alto | Média |
| Microsoft: não expor GetProtocolInfo sem autenticação | Médio | Média |
