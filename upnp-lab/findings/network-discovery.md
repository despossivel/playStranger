# Network Discovery — UPnP/SSDP Enumeration

**Data:** 2026-04-24  
**Método:** M-SEARCH UDP multicast + HTTP descriptor fetch  
**Rede:** 192.168.1.0/24

---

## Hosts Descobertos via SSDP

### 192.168.1.29 — Xbox One

```
Server:   Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0
Date:     Fri, 13 Dec 2019 02:22:26 GMT
01-NLS:   1ab7413d00bcee35709370e06a03812c
```

| UUID | Serviço |
|---|---|
| `f59636db-9bb8-4a68-a123-c59ab695077d` | MediaRenderer:1 (AVTransport, RenderingControl, ConnectionManager) |
| `33dfbafd-ed56-4013-92ae-de5bedcad72e` | DIAL:1 |
| `db0f5c91-fb57-409b-b6b1-7ee886522e08` | UUID alternativo observado em sessão diferente |

**Endpoints de controle expostos (sem autenticação):**

| Serviço | Endpoint |
|---|---|
| AVTransport | `/upnphost/udhisapi.dll?control=uuid:f59636db-...+urn:upnp-org:serviceId:AVTransport` |
| RenderingControl | `/upnphost/udhisapi.dll?control=uuid:f59636db-...+urn:upnp-org:serviceId:RenderingControl` |
| ConnectionManager | `/upnphost/udhisapi.dll?control=uuid:f59636db-...+urn:upnp-org:serviceId:ConnectionManager` |

**Informações vazadas sem autenticação:**
- Firmware: `Microsoft-Windows/10.0`
- Hardware ID: `VEN_0125&DEV_0002&REV_0001`
- Container ID: `{609C28A0-6554-4E87-86E8-27BDDBE105AE}`
- DLNA doc: `DMR-1.50`
- 200+ MIME types e perfis DLNA via `GetProtocolInfo`

---

### 192.168.1.32 — Chromecast

```
Server:        Linux/4.19.116++, UPnP/1.0, Chromecast/1.6.18
X-User-Agent:  redsonic
01-NLS:        7eb4b2c4-1dd2-11b2-aa47-a623249bda43
```

| UUID | Serviço |
|---|---|
| `b5ebad9f-5705-1ee9-0487-8a45ea61bc45` | upnp:rootdevice |

**Nota:** Chromecast usa Google Cast sobre TLS/8009 — não aceitou comandos UPnP sem handshake de pareamento. Protocolo diferente (mDNS + Cast, não SSDP + SOAP).

---

### 192.168.1.1 — Roteador (Arcadyan PRV33AX349B-B / OSP Livebox)

```
SERVER:    Unspecified, UPnP/1.0, Unspecified
LOCATION:  http://192.168.1.1:49152/wps_device.xml
```

| UUID | Serviço |
|---|---|
| `3fa3bc32-d990-f05d-38f0-c669ea6f4615` | WFADevice (WANIPConnection / IGD) |

**Serviços UPnP expostos:**
- `urn:schemas-wifialliance-org:device:WFADevice:1`
- `urn:schemas-wifialliance-org:service:WFAWLANConfig:1`

**Nota:** IGD (Internet Gateway Device) expõe `AddPortMapping` — potencial para abertura de portas no NAT sem autenticação. Não testado neste lab.

---

## Resumo de Exposição

| Host | UPnP Exposto | Autenticação | Risco |
|---|---|---|---|
| Xbox One (1.29) | AVTransport, RenderingControl, ConnectionManager | Nenhuma | ALTO |
| Chromecast (1.32) | Apenas anúncio SSDP | TLS + pareamento | BAIXO |
| Roteador (1.1) | IGD / WFAWLANConfig | Não verificado | MÉDIO |
