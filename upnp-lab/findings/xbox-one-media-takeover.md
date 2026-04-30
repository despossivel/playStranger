# PlayStranger — Unauthenticated Media Player Takeover via UPnP AVTransport (Xbox One/Series)

## Classificação

| Campo | Valor |
|---|---|
| **Nome do achado** | PlayStranger |
| **Classificacao** | Logical Vulnerability: Unauthenticated Authorization Bypass in Xbox One/Series UPnP Stack |
| **CVE** | 0-day logico no contexto Xbox One e Xbox Series (relacionado a CVE-2025-55971) |
| **CVSS v3.1** | 7.5 HIGH — `AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L` |
| **CWE** | CWE-306 (Missing Authentication) / CWE-918 (efeito SSRF secundario) |
| **OWASP** | A10:2021 — Server-Side Request Forgery |
| **Data** | 2026-04-24 |
| **Pesquisador** | Matheus Brito (@despossivel) |

---

## Descrição

O serviço UPnP `udhisapi.dll` exposto por consoles Xbox One e Xbox Series na porta TCP/2869 aceita comandos SOAP de controle de mídia (`AVTransport:1`) sem qualquer mecanismo de autenticação, pareamento ou validação de origem.

Através da action `SetAVTransportURI`, é possível forçar o console a iniciar uma requisição HTTP para uma URL controlada pelo atacante. Ao combinar isso com a action `Play`, o `NSPlayer/WMFSDK` do Xbox executa o request, expondo headers de firmware e informações de sessão ao host do atacante.

Esse comportamento caracteriza bypass de politica de seguranca no contexto do console: qualquer host na mesma rede local consegue afetar o foreground do sistema sem autorizacao explicita do usuario em Xbox One e Xbox Series.

---

## Escopo Validado

O escopo validado neste achado e o vetor `SetAVTransportURI` + `Play` sem autenticacao, com efeito observavel de App Escape e callback HTTP do `NSPlayer/WMFSDK` para host controlado.

---

## Cadeia de Exploração

```
[1] UPnP sem autenticação (CWE-306)
         ↓
[2] SetAVTransportURI aceito — URI aponta para host controlado
         ↓
[3] Play disparado — NSPlayer/WMFSDK inicia GET para host controlado
         ↓
[4] App Escape — Films & TV abre, interrompe sessão do usuário
         ↓
[5] Callback HTTP capturado com headers de firmware e UUID
```

---

## Evidências Capturadas

### Request GET recebido no listener (192.168.1.62:8080)

```
=== REQUEST ===
Path: /Video_20260310_104435_002.mp4
Headers:
  User-Agent: NSPlayer/12.00.26100.7813 WMFSDK/12.00.26100.7813
  GetContentFeatures.dlna.org: 1
  transferMode.dlna.org: Streaming
  FriendlyName.DLNA.ORG: XBOX
  Host: 192.168.1.62:8080
```

### GetPositionInfo — estado do transport após injeção (sem autenticação)

```xml
<TrackURI>http://192.168.1.62:8080/Video_20260310_104435_002.mp4</TrackURI>
<Track>1</Track>
<TrackDuration>0:00:00</TrackDuration>
<RelTime>0:00:00</RelTime>
```

### Fingerprint firmware extraído do callback

| Campo | Valor |
|---|---|
| `User-Agent` | `NSPlayer/12.00.26100.7813 WMFSDK/12.00.26100.7813` |
| `FriendlyName.DLNA.ORG` | `XBOX` |
| `GetContentFeatures.dlna.org` | `1` |
| `transferMode.dlna.org` | `Streaming` |

### GetProtocolInfo — capabilities (sem autenticação)

200+ MIME types e perfis DLNA retornados sem autenticação, incluindo:
- `video/x-ms-wmv`, `video/x-ms-asf` (parsers legados Microsoft)
- `video/x-matroska` (container complexo)
- `microsoft.com:*:application/vnd.ms-playtoapp;target="ms-playtoapp-xboxmusic":*`
- `microsoft.com:*:application/vnd.ms-playtoapp;target="ms-playtoapp-xboxvideo":*`

---

## Impacto

| Classe | Descrição |
|---|---|
| **App Escape** | Interrompe qualquer sessão ativa (jogo, filme) forçando abertura do Films & TV |
| **SSRF** | Forçar o console a fazer requests HTTP para qualquer destino alcançável |
| **Information Disclosure** | Firmware version, WMFSDK build, DLNA capabilities, UUID — sem autenticação |
| **Hardware Control** | `RenderingControl:1` aceita `SetVolume` sem autenticação |

---

## Originalidade do Achado

O CVE-2025-55971 documenta o vetor AVTransport SSRF de forma genérica em dispositivos Smart TV. O que não estava publicado:

- Confirmação do takeover na familia **Xbox One/Series**
- Captura de `NSPlayer/12.00.26100.7813 WMFSDK/12.00.26100.7813` como prova de controle
- Comportamento de **App Escape** abrindo `ms-playtoapp-xboxvideo`
- Confirmação de `RenderingControl` sem autenticação no mesmo stack

Por esse motivo, o repositório trata o caso como **PlayStranger** (0-day logico para este alvo especifico), mantendo as CVEs relacionadas como referencia tecnica.

---

## Recomendações

1. Implementar autenticação antes de aceitar qualquer action AVTransport ou RenderingControl
2. Restringir o acesso à porta 2869 via firewall a clientes emparelhados explicitamente
3. Validar e sanitizar URIs aceitas em `SetAVTransportURI` — bloquear destinos privados/arbitrários
4. Isolar o Xbox em VLAN dedicada separada de hosts não confiáveis
5. Auditar a exposição UPnP em atualizações de firmware
