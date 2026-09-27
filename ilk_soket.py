import socket

HEDEF_SITE = "example.com"
HEDEF_PORT = 80  # HTTP (şifresiz), HTTPS/443 için TLS gerekir — sıradaki adımda ekleyeceğiz

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HEDEF_SITE, HEDEF_PORT))

istek = (
    f"GET / HTTP/1.1\r\n"
    f"Host: {HEDEF_SITE}\r\n"
    f"Connection: close\r\n"
    f"\r\n"
)
sock.send(istek.encode())

cevap = b""
while True:
    parca = sock.recv(4096)
    if not parca:
        break
    cevap += parca

sock.close()

print(cevap.decode(errors="ignore"))