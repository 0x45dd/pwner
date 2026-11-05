<p align="center">
  <img src="https://raw.githubusercontent.com/0x45dd/pwner/main/docs/logo.svg" width="250" alt="pwner">
</p>

<p align="center">
  Konuşarak kullandığın, ajan tabanlı bir ağ sızma testi aracı.
</p>

<p align="center">
  <a href="https://pypi.org/project/pwner/"><img
    src="https://img.shields.io/pypi/v/pwner?color=4c4a42&label=pypi"
    alt="pwner on PyPI"></a>
  <a href="https://github.com/0x45dd/pwner/blob/main/LICENSE"><img
    src="https://img.shields.io/github/license/0x45dd/pwner?color=4c4a42&label=license"
    alt="Lisans: AGPL-3.0-or-later"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-4c4a42" alt="Python 3.10+">
</p>

<p align="center">
  <a href="https://github.com/0x45dd/pwner/blob/main/README.md">English</a> &nbsp;·&nbsp;
  <a href="https://github.com/0x45dd/pwner/blob/main/README.es.md">Español</a> &nbsp;·&nbsp;
  <a href="https://github.com/0x45dd/pwner/blob/main/README.de.md">Deutsch</a> &nbsp;·&nbsp;
  <a href="https://github.com/0x45dd/pwner/blob/main/README.ja.md">日本語</a> &nbsp;·&nbsp;
  <b>Türkçe</b>
</p>

> Bu, [README.md](https://github.com/0x45dd/pwner/blob/main/README.md) dosyasının özet çevirisidir. Tam komut ve yapılandırma
> referansı yalnızca İngilizcedir. Bir çelişki görürsen İngilizce metin geçerlidir.

`pwner`, terminalinden bir ağ sızma testini planlayıp yürüten, LLM tarafından sürülen bir
ajandır. Hostları keşfeder, servisleri parmak izinden tanır, bilinen zafiyetlere karşı
kontrol eder ve — hedef gerektiriyorsa ve **sen** onaylarsan — etkiyi kanıtlamak için
sömürür. Araçları simüle etmez, gerçeğini çalıştırır (nmap, nuclei, netexec, impacket,
hydra ve diğerleri) ve doğrulanmış bulguları önem derecesi, kanıt ve çözümüyle raporlar.

Kendi modelinle çalışır, ya da hiç model olmadan.

- **Onunla konuşuyorsun.** Flag kalabalığı yok: *"tara, veritabanına odaklan"* dersin,
  neyi çalıştıracağına kendisi karar verir, muhakemesini sen izlerken gösterir ve
  çalışma ortasında yönünü değiştirebilirsin.
- **Scope kod içinde zorlanır.** Her tool çağrısı, çalışmadan önce senin belirttiğin
  hedefe karşı kontrol edilir — modele prompt içinde rica edilerek değil.
- **Müdahaleci aksiyonlar varsayılan olarak reddedilir.** Brute-force, uzaktan komut
  çalıştırma, kimlik bilgisi dökümü ve reverse shell için açık onayın gerekir.
- **Kendi modelin, kendi makinen.** OpenAI, Anthropic, Google, DeepSeek ya da kendi
  donanımındaki bir sunucu — Ollama, Lemonade, llama.cpp, OpenAI uyumlu her şey. Yerel
  bir endpoint için API key gerekmez. Sen yapılandırmadan hiçbir yere hiçbir şey gitmez.
- **Modelsiz de çalışır.** `--no-ai`, keşif → parmak izi → tespit hattının tamamını
  deterministik biçimde çalıştırır; API key yok, makineden hiçbir şey çıkmıyor.
- **PCI DSS segmentasyon testi.** `pwner pci`, kapsam dışı bir segmentten CDE'nin izole
  olup olmadığını sınar (11.4.5/11.4.6); deterministik olduğu için düzeltmeden sonra tekrar
  koşmak 11.4.4'ün istediği retest olur. Tek başına uyumluluk sağlamaz.
- **52 tool**: nmap, HTTP, servis bazlı problar, Active Directory ve kimlik bilgisi
  işleri. Her biri standart binary'nin ince bir sarmalayıcısı, yeniden yazımı değil.

## Güvenlik modeli

İki mekanizma, ikisi de tool katmanında, ikisi de modelin erişemediği yerde.

**Scope kilidi.** [`build_dispatch`](https://github.com/0x45dd/pwner/blob/main/pwner/tools/core.py) her tool'u sarar; host taşıyan
her argüman, tool gövdesi çalışmadan *önce* senin hedefine karşı kontrol edilir. Tool'lar
varsayılan olarak scope içindedir: kendi kontrolünü yapmayı unutan bir tool bile korunur,
kayıtlı olmayan bir tool adı ise kapalı başarısız olur. Bir network argümanının tamamen
yetkilendirmenin içinde kalması gerekir.

Muhafızın kontrol edemediği tek şey `set_target`, çünkü argümanı *yeni scope'un kendisi*.
Bu yüzden kendi kapısı var: daraltmak serbest, zaten yetkilendirdiğinin dışına çıkmak her
seferinde senin cevabını istiyor, ve `--auto-consent` bunu kapsamıyor.

**Onay kapısı.** Aktif olan her şey, o oturumda sen onaylamadıkça reddedilir. Onay modelin
dışında çözülür — ajan kendi kendini onaylayamaz — ve etkileşimsiz bir çalıştırma, onu
`--auto-consent` ile başlatmadıysan reddeder.

Reddedilme, çalışmayı durduran bir hata değildir: modele tool sonucu olarak geri döner,
böylece ajan sınırı aştığını öğrenir ve sınırın içinde devam eder.

Kod tabanında en çok test edilen kısım bunlar: scope sınırında
[`tests/test_scope.py`](https://github.com/0x45dd/pwner/blob/main/tests/test_scope.py) içinde 77 test, onay kapısında
[`tests/test_consent.py`](https://github.com/0x45dd/pwner/blob/main/tests/test_consent.py) içinde 13 test — toplam 785 testin içinden.
Bunu bir ağa doğrultmadan önce tek bir şey okuyacaksan, onları oku.

Kullanım amacı:

- Yazılı izinle ve mutabık kalınmış bir scope ile yapılan yetkili sızma testleri
- Programın belirttiği kuralların içinde bug bounty çalışması
- Kendi lab'ın, kendi donanımın, CTF'ler
- Sahibi olduğun sistemler üzerinde güvenlik araştırması

Bu aracın amacı olmayan ve savunulamayacak olan:

- Sahibi olmadığın ve test etmek için yazılı iznin bulunmadığı herhangi bir host
- Üzerinde bulunduğun bir ağı "şöyle bir kontrol etmek"
- Kimin yetkilendirdiğini söyleyemediğin herhangi bir şey

## Kurulum

Python **3.10+**. **Tek zorunlu gereksinim nmap** — diğer her şey daha fazla tool açar
ve opsiyoneldir.

```bash
curl -fsSL https://raw.githubusercontent.com/0x45dd/pwner/main/install.sh | bash
```

Bu komut `~/.local/share/pwner` altında izole bir virtualenv kurar, sistem Python'una
dokunmaz ve `pwner`'ı PATH'ine ekler; böylece her dizinden çalışır. `--with-tools`
eklersen nmap ve opsiyonel tarayıcıları da kurar, `--uninstall` ise hepsini geri alır.

PyPI'da da var, kendi Python araçlarını kullanmayı tercih ediyorsan:

```bash
pipx install pwner      # izole kurar, `pwner` PATH'ine düşer
uv tool install pwner   # aynısı, uv ile
pip install pwner       # bir virtualenv içinde
```

Düz `pip install` yerine `pipx` ya da `uv tool` kullan: kurulum scriptinin verdiği izolasyonu
veriyorlar, ayrıca sistem Python'una kurmak güncel dağıtımların çoğunda zaten reddediliyor.

macOS'ta ayrıca bir tap var:

```bash
brew install 0x45dd/tap/pwner
```

Bu nmap'i de beraberinde getirir. Kaynaktan kurmak için:

```bash
git clone https://github.com/0x45dd/pwner.git
cd pwner
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
./scripts/install-deps.sh   # brew/apt/kali/pacman/dnf
pwner doctor                # neyin eksik olduğunu söyler
```

**Kali'de kurulacak neredeyse hiçbir şey yok.** Varsayılan bir Kali imajı, pwner'ın
sürdüğü 11 harici tool'dan 8'ini zaten getiriyor. `sudo apt install nuclei bloodhound.py`
ikisini daha ekler; paketlenmemiş olan tek şey kerbrute. pwner, Kali'yi Debian olarak
değil kendi ekosistemi olarak algılar, bu yüzden `pwner doctor` sana düz bir Debian'ın
gerektirdiği kaynak derlemeleri yerine apt komutları verir. Nerede çalıştıracağını
seçiyorsan, orada çalıştır.

## İlk çalıştırma

```bash
pwner
```

İlk çalıştırma bir kez provider ve API key sorar, bunları `~/.config/pwner/config.json`
dosyasına kaydeder (yalnızca sahibi okuyabilir). Sonraki her çalıştırma seni doğrudan
oturuma düşürür. Sonra değiştirmek için `pwner --pick` (provider/model menüsü), `pwner setup` (baştan
tüm sorular) ya da çalışan bir oturumun içinden `/model` ve `/provider`.

```bash
pwner chat 10.0.0.5          # oturum, hedef atanmış
pwner 10.0.0.0/24 --no-ai    # tarama, modelsiz
pwner doctor                 # tool durumu
```

Oturum içinde ajanla konuşur ve çalışırken onu yönlendirirsin. `/help` komutları listeler,
`/findings` ve `/topology` o ana kadar kurduğu tabloyu gösterir, `/dump` ise transkripti
`~/.local/share/pwner/sessions/` altına yazar (yalnızca sahibi okuyabilir — çalışmanın
ortaya çıkardığı her kimlik bilgisini düz metin olarak içerir).

## Modelin

Bir provider'a yönlendir ve key ver. Hazır ayarlar OpenAI, Anthropic, Google ve DeepSeek'i
kapsar; OpenAI API'si konuşan başka her şey `--base-url` ile çalışır.

```bash
export PWNER_API_KEY=...
pwner chat 10.0.0.5 --provider anthropic
```

Modelin tool calling desteklemesi gerekir. `pwner chat --help` hazır ayarları ve tüm
geçersiz kılmaları listeler.

### Kendi donanımında

`ollama` ve `lemonade` de hazır ayardır ve yerel bir endpoint için **API key gerekmez** —
verilirse yine gönderilir, çünkü Lemonade inference ve admin key'lerini birbirinden ayırır.

```bash
pwner chat 10.0.0.5 --provider ollama
pwner chat 10.0.0.5 --provider lemonade
```

Yerel sunucular, o makinenin indirdiği modelin adıyla anılır; bu yüzden mantıklı bir
varsayılan model yok. Hiçbiri ayarlanmamışsa pwner sunucunun `/models` endpoint'ine sorar
ve bulduğunu kullanır; `pwner setup` bunları listeler ve kaydetmek için birini seçmene
izin verir. OpenAI uyumlu diğer sunucular — llama.cpp, LM Studio, vLLM — `--base-url` ile
aynı şekilde çalışır ve URL loopback'e veya özel bir ağa işaret ettiğinde key'siz kabul
edilir.

```bash
pwner chat 10.0.0.5 --base-url http://192.168.1.50:13305/api/v1 --model Qwen3-Coder-30B
```

## Modelsiz çalıştırma

`--no-ai` deterministik seti çalıştırır: host keşfi, port taraması, servis tespiti, OS
parmak izi ve bilinen zafiyet tespiti, ardından aynı bulgu raporu. API key yok, taramanın
kendisi dışında ağ çağrısı yok ve tekrarlanabilir — bu da onu CI'da, air-gapped bir
çalışmada veya verinin binadan çıkamayacağı durumlarda kullanılacak mod yapar.

Aktif tool'lar ajanın tool'larıdır; hem model hem de senin onayın gerekir.

## Dokümantasyon

Tam komut ve yapılandırma referansı, ajan döngüsü, modül kataloğu ve kurallar
**[pwner.si](https://www.pwner.si/)** adresinde — yalnızca İngilizce:

- [Docs](https://www.pwner.si/docs) — kurulum, ilk oturum, her komut ve flag
- [Agent](https://www.pwner.si/agent) — döngü nasıl çalışır, neyi yapabilir neyi yapamaz
- [Modules](https://www.pwner.si/modules) — 52 tool ve her birinin neyi sürdüğü
- [Rules](https://www.pwner.si/rules) — scope, onay, sorumlu kullanım
- [Contributing](https://github.com/0x45dd/pwner/blob/main/CONTRIBUTING.md) — geliştirme ortamı, tools paketi, tool ekleme
- [Security](https://github.com/0x45dd/pwner/blob/main/SECURITY.md) — pwner'ın kendisindeki bir zafiyeti bildirmek

## İletişim

Herkese açık bir issue'ya uygun olmayan her şey için — sorular, özel geri bildirim ya da
doğrudan ulaşmak — [berk@planckproof.ai](mailto:berk@planckproof.ai) adresine yazabilirsin.

Hatalar ve özellik istekleri [issue](https://github.com/0x45dd/pwner/issues) olarak daha iyi işler; güvenlik zafiyetleri
ise bir düzeltme çıkana kadar özel kalsın diye [SECURITY.md](https://github.com/0x45dd/pwner/blob/main/SECURITY.md) üzerinden gitmeli.

## Lisans

[GNU AGPL-3.0-or-later](https://github.com/0x45dd/pwner/blob/main/LICENSE). Copyright (C) 2026 Berk D.

Güçlü copyleft, ağ maddesiyle: pwner'ı değiştirip başkalarının ağ üzerinden kullanmasına
izin verirsen, değiştirdiğin kaynağı da onlara borçlusun.

> [!WARNING]
> **Yalnızca yetkili kullanım.** pwner, adını verdiğin hostlara gerçek trafik gönderir ve
> senin onayınla onlara aktif olarak sızar. Yalnızca sahibi olduğun ya da test etmek için
> açık ve yazılı iznin bulunduğu sistemlere karşı çalıştır ve mutabık kalınan scope'un
> içinde kal. Yetkisiz test, çoğu hukuk düzeninde suçtur.
> O yetkiyi almak aracın değil senin sorumluluğundur. pwner olduğu gibi sunulur; hiçbir
> garanti ve kötüye kullanımdan doğacak hiçbir sorumluluk taşımaz. Scope kilidi ve onay
> kapısı birer mühendislik önlemidir, hukuki savunma değil.
