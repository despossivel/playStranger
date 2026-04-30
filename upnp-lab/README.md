# UPnP Lab — Xbox One/Series & IoT Security Research

> **DISCLAIMER:** Este repositório documenta testes realizados exclusivamente em ambiente de laboratório doméstico, em dispositivos de propriedade do pesquisador. Nenhum sistema de terceiros foi afetado. O conteúdo é de uso exclusivo para fins educacionais e de divulgação responsável.

---

## Descrição

Lab de enumeração UPnP/SSDP e exploração de vulnerabilidades lógicas em dispositivos IoT e gaming conectados à mesma rede local. O foco principal é a ausência de autenticação no serviço UPnP AVTransport exposto por consoles Xbox One e Xbox Series, que permite controle remoto do media player sem pareamento ou credenciais.

---

## Topologia da Rede

```
192.168.1.0/24

  192.168.1.1    Roteador   OSP Livebox / Arcadyan PRV33AX349B-B (OpenWRT 12.09.1)
                            porta 49152 — UPnP IGD (WANIPConnection)
                            porta 1900  — SSDP

  192.168.1.29   Xbox One   Microsoft Xbox One (MediaRenderer:1 + DIAL:1)
                            porta 2869  — UPnP/udhisapi.dll
                            porta 1900  — SSDP
                            Server: Microsoft-Windows/10.0 UPnP/1.0

  192.168.1.32   Chromecast Google Chromecast
                            porta 8008  — Google Cast (TLS)
                            porta 1900  — mDNS/SSDP
                            Server: Linux/4.19.116++, Chromecast/1.6.18

  192.168.1.62   Atacante   macOS — host de controle e listener HTTP
```

---

## CVEs Relacionados

| CVE | Descrição |
|---|---|
| [CVE-2025-55971](https://nvd.nist.gov/vuln/detail/CVE-2025-55971) | UPnP AVTransport SSRF em dispositivos de mídia (Smart TVs / MediaRenderers) |

O achado principal deste lab foi batizado como **PlayStranger** e classificado como 0-day logico no contexto do console: uma vulnerabilidade logica de **Bypass de Autorizacao sem autenticacao** na stack UPnP de Xbox One e Xbox Series.

- **Classe:** CWE-306 (Missing Authentication for Critical Function)
- **Vetor validado:** `SetAVTransportURI` + `Play` sem autenticacao
- **Impacto observado:** Remote UI Hijacking e Application Interruption (App Escape), com interrupcao de sessao ativa e abertura forcada do player

Em outras palavras: nao e apenas exfiltracao/SSRF de rede. Ha efeito direto sobre a interface e o foreground do sistema, o que caracteriza impacto de seguranca distinto na familia Xbox (One/Series).

---

## Foco Tecnico do Achado

O achado validado neste lab permanece focado em `SetAVTransportURI` + `Play` sem autenticacao, com execucao de requests HTTP pelo stack `NSPlayer/WMFSDK` para host controlado e impacto direto na sessao ativa do usuario.

---

## Estrutura do Repositório

```
upnp-lab/
├── README.md
├── findings/
│   ├── xbox-one-media-takeover.md   # Achado principal (PlayStranger)
│   └── network-discovery.md         # Enumeração completa da rede
├── evidence/
│   ├── ssdp-discovery.txt           # Respostas SSDP brutas capturadas
│   ├── callback-capture.txt         # Headers HTTP capturados no listener
│   └── device-descriptors/
│       ├── xbox-mediarenderer.xml   # Descriptor UPnP do Xbox (MediaRenderer)
│       ├── xbox-dial.xml            # Descriptor DIAL do Xbox
│       └── router-igd.xml           # Descriptor IGD do roteador
├── exploits/
│   ├── 01-ssdp-discovery.py         # Enumeração SSDP via M-SEARCH
│   ├── 02-device-fingerprint.sh     # Coleta de descriptors via HTTP
│   ├── 03-avtransport-ssrf.sh       # SetAVTransportURI + Play (SSRF)
│   └── server.py                    # Listener HTTP para captura de callbacks
└── report/
    └── findings-summary.md          # Resumo executivo de todos os achados
```
