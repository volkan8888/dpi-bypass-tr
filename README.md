## Kullanım

**Önemli:** Bu araçlar Windows ağ sürücüsü (WinDivert) kullanır. Windows, hiçbir programın kullanıcı onayı olmadan ağ sürücüsü çalıştırmasına izin vermez — bu yüzden **yönetici izni zorunludur** (GoodbyeDPI gibi benzer tüm araçlarda da aynı gereklilik vardır).

### Hazır .exe ile (Python kurulumu gerektirmez)

1. [Releases](https://github.com/volkan8888/dpi-bypass-tr/releases) sayfasından `SNIBypass.exe` veya `DNSBypass.exe` dosyasını indir.
2. Dosyaya **sağ tık → "Run as administrator"** seç.
   *(Direkt çift tıklama, izin isteme penceresi çıkarmadan sessizce başarısız olabilir — bu yüzden sağ tık menüsünü kullanmak garantidir.)*

### Kaynak koddan

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Terminali **yönetici olarak** açıp (Başlat menüsü → sağ tık → "Terminal (Yönetici)"):

```bash
python sni_bypass.py
python dns_bypass.py
```