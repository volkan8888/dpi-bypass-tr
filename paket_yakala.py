import pydivert

def sni_bul(veri: bytes):
    """SNI'yi bulur, hem ismi hem de paketin içindeki başlangıç/bitiş konumunu döner"""
    try:
        if len(veri) < 6 or veri[0] != 0x16:
            return None, None, None

        pos = 5
        if veri[pos] != 0x01:
            return None, None, None
        pos += 4

        pos += 2   # Client Version
        pos += 32  # Random

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

            if ext_type == 0x0000:  # server_name extension
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
    print("Fragmentation aktif... (durdurmak için Ctrl+C)")

    for paket in w:
        veri = paket.tcp.payload

        if veri and len(veri) > 5 and veri[0] == 0x16 and veri[1] == 0x03:
            sni, baslangic, bitis = sni_bul(veri)

            if sni:
                print(f"### BÖLÜNÜYOR: {sni} ###")

                # SNI'nin TAM ORTASINDAN bölüyoruz
                bolme_noktasi = baslangic + (bitis - baslangic) // 2

                birinci_yari = veri[:bolme_noktasi]
                ikinci_yari = veri[bolme_noktasi:]

                # --- 1. PAKET ---
                paket1 = paket.raw  # orijinal paketin ham (raw) halini şablon olarak kullan
                paket.tcp.payload = birinci_yari
                w.send(paket)

                # --- 2. PAKET ---
                # sequence number'ı, birinci parçanın uzunluğu kadar ileri kaydırıyoruz
                paket.tcp.seq_num += len(birinci_yari)
                paket.tcp.payload = ikinci_yari
                w.send(paket)

                continue  # bu paketi normal yoldan GÖNDERME, zaten iki parça halinde gönderdik

        w.send(paket)