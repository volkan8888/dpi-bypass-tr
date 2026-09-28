import pydivert
import socket
import requests
import threading

VERBOSE = False  # True yaparsan her sorguyu görürsün, False'ta sessiz çalışır

def dns_uzerinden_gercek_ip(domain):
    try:
        r = requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": domain, "type": "A"},
            headers={"accept": "application/dns-json"},
            timeout=3
        )
        data = r.json()
        for cevap in data.get("Answer", []):
            if cevap["type"] == 1:
                return cevap["data"]
    except Exception:
        pass
    return None


def dns_sorgusunu_ayikla(veri: bytes):
    try:
        pos = 12
        etiketler = []
        while veri[pos] != 0:
            uzunluk = veri[pos]
            pos += 1
            etiketler.append(veri[pos:pos+uzunluk].decode())
            pos += uzunluk
        domain = ".".join(etiketler)
        return domain, pos + 5
    except Exception:
        return None, None


def sahte_dns_cevabi_olustur(orijinal_sorgu, soru_bitis, ip):
    transaction_id = orijinal_sorgu[0:2]
    flags = b"\x81\x80"
    qdcount = b"\x00\x01"
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = transaction_id + flags + qdcount + ancount + nscount + arcount
    soru_kismi = orijinal_sorgu[12:soru_bitis]
    cevap = b"\xc0\x0c"
    cevap += b"\x00\x01"
    cevap += b"\x00\x01"
    cevap += b"\x00\x00\x00\x3c"
    cevap += b"\x00\x04"
    cevap += socket.inet_aton(ip)
    return header + soru_kismi + cevap


DURDUR = False

def kapatma_dinleyici(w):
    """Kullanıcı Enter'a basınca akışı temiz şekilde durdurur"""
    input()  # Enter beklenir
    global DURDUR
    DURDUR = True
    w.close()  # WinDivert'i kapatıp bloklanmış recv'i serbest bırakır


def calistir():
    filtre = "outbound and udp.DstPort == 53"

    with pydivert.WinDivert(filtre) as w:
        print("DNS-bypass aktif. Durdurmak için ENTER'a bas (Ctrl+C değil!)\n")

        dinleyici = threading.Thread(target=kapatma_dinleyici, args=(w,), daemon=True)
        dinleyici.start()

        try:
            for paket in w:
                if DURDUR:
                    break

                veri = paket.udp.payload
                domain, soru_bitis = dns_sorgusunu_ayikla(veri)

                if domain:
                    gercek_ip = dns_uzerinden_gercek_ip(domain)

                    if gercek_ip:
                        if VERBOSE:
                            print(f"[DNS] {domain} -> {gercek_ip}")

                        cevap_verisi = sahte_dns_cevabi_olustur(veri, soru_bitis, gercek_ip)

                        kaynak_ip, kaynak_port = paket.src_addr, paket.src_port
                        paket.src_addr, paket.src_port = paket.dst_addr, paket.dst_port
                        paket.dst_addr, paket.dst_port = kaynak_ip, kaynak_port
                        paket.udp.payload = cevap_verisi
                        paket.direction = pydivert.Direction.INBOUND

                        w.send(paket, recalculate_checksum=True)
                        continue

                w.send(paket)
        except OSError:
            pass  # w.close() çağrıldığında recv burada "hata" fırlatır, bu normal, sessizce çık

    print("\nDurduruldu.")


if __name__ == "__main__":
    calistir()