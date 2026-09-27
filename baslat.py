import subprocess
import pydivert

# ============ 1. ADIM: DNS'i otomatik düzelt ============
def dns_ayarla():
    try:
        # Aktif ağ arayüzünün adını bul (genelde "Wi-Fi")
        arayuz_adi = "Wi-Fi"
        subprocess.run(
            ["netsh", "interface", "ip", "set", "dns", arayuz_adi, "static", "1.1.1.1"],
            check=True, capture_output=True
        )
        subprocess.run(
            ["netsh", "interface", "ip", "add", "dns", arayuz_adi, "8.8.8.8", "index=2"],
            check=True, capture_output=True
        )
        subprocess.run(["ipconfig", "/flushdns"], check=True, capture_output=True)
        print("[✓] DNS ayarlandı: 1.1.1.1 / 8.8.8.8")
    except Exception as e:
        print(f"[!] DNS ayarlanamadı: {e}")
        print("    (Script'i 'Yönetici olarak' çalıştırdığından emin ol)")


# ============ 2. ADIM: SNI Fragmentation ============
def sni_bul(veri: bytes):
    try:
        if len(veri) < 6 or veri[0] != 0x16:
            return None, None, None
        pos = 5
        if veri[pos] != 0x01:
            return None, None, None
        pos += 4
        pos += 2
        pos += 32
        session_id_len = veri[pos]
        pos += 1 + session_id_len
        cipher_suites_len = int.from_bytes(veri[pos:pos+2], "big")
        pos += 2 + cipher_suites_len
        compression_len = veri[pos]
        pos += 1 + compression_len
        extensions_len = int.from_bytes(veri[pos:pos+2], "big")
        pos += 2
        extensions_end = pos + extensions_len
        while pos < extensions_end:
            ext_type = int.from_bytes(veri[pos:pos+2], "big")
            ext_len = int.from_bytes(veri[pos+2:pos+4], "big")
            pos += 4
            if ext_type == 0x0000:
                hostname_len = int.from_bytes(veri[pos+3:pos+5], "big")
                hostname_start = pos + 5
                hostname_end = hostname_start + hostname_len
                hostname = veri[hostname_start:hostname_end].decode()
                return hostname, hostname_start, hostname_end
            pos += ext_len
        return None, None, None
    except Exception:
        return None, None, None


def bypass_baslat():
    filtre = "outbound and tcp.DstPort == 443"
    print("[✓] SNI-fragmentation aktif. Her siteye giden trafik bölünüyor.")
    print("Durdurmak için Ctrl+C\n")

    with pydivert.WinDivert(filtre) as w:
        for paket in w:
            veri = paket.tcp.payload
            if veri and len(veri) > 5 and veri[0] == 0x16 and veri[1] == 0x03:
                sni, baslangic, bitis = sni_bul(veri)
                if sni:
                    orta = baslangic + (bitis - baslangic) // 2
                    parca1 = veri[:orta]
                    parca2 = veri[orta:]
                    paket.tcp.payload = parca1
                    w.send(paket)
                    paket.tcp.seq_num += len(parca1)
                    paket.tcp.payload = parca2
                    w.send(paket)
                    continue
            w.send(paket)


if __name__ == "__main__":
    dns_ayarla()
    bypass_baslat()