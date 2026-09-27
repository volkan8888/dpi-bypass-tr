import socket
import ssl

HEDEF_SITE = "example.com"
HEDEF_PORT = 443  # HTTPS

# 1. Normal TCP soketi kur (öncekiyle aynı)
ham_soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ham_soket.connect((HEDEF_SITE, HEDEF_PORT))

# 2. SSL/TLS bağlamı oluştur (varsayılan güvenlik ayarlarıyla)
context = ssl.create_default_context()

# 3. Ham soketi TLS ile "sarmala" (wrap) — server_hostname çok önemli,
#    bu bizim gönderdiğimiz SNI alanı olacak!
tls_soket = context.wrap_socket(ham_soket, server_hostname=HEDEF_SITE)

print("TLS handshake tamamlandı!")
print("Sunucunun kullandığı şifreleme:", tls_soket.cipher())

# 4. Şimdi normal HTTP isteğini bu şifreli kanaldan gönderiyoruz
istek = (
    f"GET / HTTP/1.1\r\n"
    f"Host: {HEDEF_SITE}\r\n"
    f"Connection: close\r\n"
    f"\r\n"
)
tls_soket.send(istek.encode())

cevap = b""
while True:
    parca = tls_soket.recv(4096)
    if not parca:
        break
    cevap += parca

tls_soket.close()
print(cevap.decode(errors="ignore"))