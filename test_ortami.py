import pydivert

TEST_DOMAIN = "python.org"   # test hedefimiz - gerçekten engelli olmayan, güvenilir bir site
BYPASS_ACTIVE = True     # ÖNCE False ile test et, sonra True yapıp tekrar test edeceğiz

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


filtre = "outbound and tcp.DstPort == 443"

with pydivert.WinDivert(filtre) as w:
    print(f"Sahte DPI çalışıyor. BYPASS_ACTIVE = {BYPASS_ACTIVE}")
    print(f"Test hedefi: {TEST_DOMAIN}")
    print("(durdurmak için Ctrl+C)\n")

    for paket in w:
        veri = paket.tcp.payload

        if veri and len(veri) > 5 and veri[0] == 0x16 and veri[1] == 0x03:
            sni, baslangic, bitis = sni_bul(veri)

            if sni and TEST_DOMAIN in sni:
                if not BYPASS_ACTIVE:
                    print(f"### ENGELLENDİ (paket düşürüldü): {sni} ###")
                    continue  # paketi hiç göndermiyoruz -> bağlantı asla kurulmayacak

                else:
                    print(f"### BYPASS AKTİF, bölünüyor: {sni} ###")
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