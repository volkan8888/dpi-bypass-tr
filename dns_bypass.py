import pydivert
import socket
import requests

def dns_uzerinden_gercek_ip(domain):
    """ISP'nin göremeyeceği bir yoldan (DoH/HTTPS), gerçek IP'yi Cloudflare'e soruyoruz"""
    try:
        r = requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": domain, "type": "A"},
            headers={"accept": "application/dns-json"},
            timeout=3
        )
        data = r.json()
        for cevap in data.get("Answer", []):
            if cevap["type"] == 1:  # A kaydı (IPv4)
                return cevap["data"]
    except Exception as e:
        print(f"  [DoH hatası] {e}")
    return None


def dns_sorgusunu_ayikla(veri: bytes):
    """Yakalanan DNS sorgusunun içinden domain adını çıkarır"""
    try:
        pos = 12  # DNS header sabit 12 byte
        etiketler = []
        while veri[pos] != 0:
            uzunluk = veri[pos]
            pos += 1
            etiketler.append(veri[pos:pos+uzunluk].decode())
            pos += uzunluk
        domain = ".".join(etiketler)
        return domain, pos + 5  # null byte + type(2) + class(2)
    except Exception:
        return None, None


def sahte_dns_cevabi_olustur(orijinal_sorgu: bytes, soru_bitis: int, ip: str) -> bytes:
    """Gerçek IP ile, DNS protokolüne uygun bir 'cevap' paketi inşa eder"""
    transaction_id = orijinal_sorgu[0:2]  # aynı ID'yi kullanmak ZORUNLU, yoksa uygulama cevabı tanımaz
    flags = b"\x81\x80"      # "standart, başarılı cevap" bayrağı
    qdcount = b"\x00\x01"
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = transaction_id + flags + qdcount + ancount + nscount + arcount

    soru_kismi = orijinal_sorgu[12:soru_bitis]  # soruyu aynen kopyala (DNS kuralı böyle)

    cevap = b"\xc0\x0c"            # isim: soruya işaret eden pointer
    cevap += b"\x00\x01"            # type: A
    cevap += b"\x00\x01"            # class: IN
    cevap += b"\x00\x00\x00\x3c"    # TTL: 60 saniye
    cevap += b"\x00\x04"            # veri uzunluğu: 4 byte
    cevap += socket.inet_aton(ip)   # gerçek IP burada

    return header + soru_kismi + cevap


filtre = "outbound and udp.DstPort == 53"

print("DNS-bypass aktif. (Ctrl+C ile durdur)\n")

with pydivert.WinDivert(filtre) as w:
    for paket in w:
        veri = paket.udp.payload
        domain, soru_bitis = dns_sorgusunu_ayikla(veri)

        if domain:
            print(f"[DNS sorgusu] {domain}")
            gercek_ip = dns_uzerinden_gercek_ip(domain)

            if gercek_ip:
                print(f"  -> gerçek IP: {gercek_ip}")
                cevap_verisi = sahte_dns_cevabi_olustur(veri, soru_bitis, gercek_ip)

                # Paketi "cevap" haline çeviriyoruz: kaynak/hedef yer değiştiriyor
                kaynak_ip, kaynak_port = paket.src_addr, paket.src_port
                paket.src_addr, paket.src_port = paket.dst_addr, paket.dst_port
                paket.dst_addr, paket.dst_port = kaynak_ip, kaynak_port
                paket.udp.payload = cevap_verisi
                paket.direction = pydivert.Direction.INBOUND

                w.send(paket, recalculate_checksum=True)
                continue

        w.send(paket)  # DoH başarısızsa orijinal sorguyu olduğu gibi gönder