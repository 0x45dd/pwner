<p align="center">
  <img src="docs/logo.svg" width="250" alt="pwner">
</p>

<p align="center">
  Ein agentisches Netzwerk-Pentest-Werkzeug, mit dem du sprichst.
</p>

<p align="center">
  <a href="LICENSE"><img
    src="https://img.shields.io/github/license/0x45dd/pwner?color=4c4a42&label=license"
    alt="Lizenz: AGPL-3.0-or-later"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-4c4a42" alt="Python 3.10+">
</p>

<p align="center">
  <a href="README.md">English</a> &nbsp;·&nbsp;
  <a href="README.es.md">Español</a> &nbsp;·&nbsp;
  <b>Deutsch</b> &nbsp;·&nbsp;
  <a href="README.ja.md">日本語</a> &nbsp;·&nbsp;
  <a href="README.tr.md">Türkçe</a>
</p>

> Dies ist eine gekürzte Übersetzung von [README.md](README.md). Die vollständige Befehls-
> und Konfigurationsreferenz gibt es nur auf Englisch. Bei Widersprüchen gilt der englische
> Text.

`pwner` ist ein LLM-gesteuerter Agent, der einen Netzwerk-Penetrationstest aus deinem
Terminal heraus plant und durchführt. Er findet Hosts, erkennt Dienste per Fingerprinting,
prüft sie gegen bekannte Schwachstellen und — wenn das Ziel es rechtfertigt und **du** es
freigibst — exploitet er sie, um die Auswirkung zu belegen. Er fährt echte Werkzeuge (nmap,
nuclei, netexec, impacket, hydra und weitere), statt sie zu simulieren, und berichtet
bestätigte Findings mit Schweregrad, Nachweis und Behebung.

Er läuft mit deinem eigenen Modell — oder ganz ohne Modell.

- **Du sprichst mit ihm.** Keine Flag-Suppe: du sagst *„scanne es, konzentriere dich auf die
  Datenbank"*, und er entscheidet selbst, was er ausführt, zeigt dir unterwegs seine
  Überlegungen, und du kannst ihn mitten im Lauf umlenken.
- **Der Scope wird im Code erzwungen.** Jeder Tool-Aufruf wird gegen das von dir genannte
  Ziel geprüft, bevor er läuft — nicht per Prompt vom Modell erbeten.
- **Eingreifende Aktionen sind standardmäßig verboten.** Brute Force, Remote-Code-
  Ausführung, das Auslesen von Zugangsdaten und Reverse Shells brauchen deine ausdrückliche
  Freigabe.
- **Dein Modell, deine Maschine.** OpenAI, Anthropic, Google, DeepSeek oder ein Server auf
  deiner eigenen Hardware — Ollama, Lemonade, llama.cpp, alles OpenAI-kompatible. Ein
  lokaler Endpoint braucht keinen API-Key. Nichts verlässt die Maschine, bis du es
  konfigurierst.
- **Funktioniert ohne Modell.** `--no-ai` fährt die komplette Kette aus Discovery →
  Fingerprinting → Erkennung deterministisch, ohne API-Key, und nichts verlässt die
  Maschine.
- **PCI-DSS-Segmentierungstest.** `pwner pci` prüft aus einem Out-of-Scope-Segment, ob
  die CDE isoliert ist (11.4.5/11.4.6); weil er deterministisch ist, ist ein erneuter Lauf
  nach dem Fix der von 11.4.4 geforderte Retest. Compliance entsteht dadurch nicht.
- **52 Werkzeuge** über nmap, HTTP, dienstspezifische Probes, Active Directory und Arbeit
  mit Zugangsdaten — jedes ein dünner Wrapper um die Standard-Binary, keine
  Neuimplementierung.

## Sicherheitsmodell

Zwei Mechanismen, beide in der Tool-Schicht, beide außerhalb der Reichweite des Modells.

**Scope-Sperre.** [`build_dispatch`](pwner/tools/core.py) umhüllt jedes Werkzeug, sodass
jedes Argument, das einen Host trägt, gegen dein Ziel geprüft wird, *bevor* der Rumpf des
Werkzeugs läuft. Werkzeuge sind standardmäßig im Scope: eines, das seine eigene Prüfung
vergisst, ist trotzdem abgesichert, und ein nicht registrierter Werkzeugname schlägt
geschlossen fehl. Ein Netzwerk-Argument muss vollständig innerhalb der Autorisierung liegen.

Das Einzige, was der Wächter nicht prüfen kann, ist `set_target`, denn dessen Argument
*ist* der neue Scope. Dafür hat es ein eigenes Gate: Verengen ist frei, alles andere
braucht jedes Mal deine Antwort, und `--auto-consent` deckt es nicht ab.

**Freigabe-Gate.** Alles Aktive wird verweigert, solange du es in dieser Sitzung nicht
freigibst. Die Freigabe wird außerhalb des Modells aufgelöst — der Agent kann sich nicht
selbst freigeben — und in einem nicht-interaktiven Lauf lautet die Antwort immer nein.

Eine Verweigerung ist kein Fehler, der den Lauf abbricht: sie geht als Tool-Ergebnis an das
Modell zurück, sodass der Agent lernt, dass er zu weit gegriffen hat, und innerhalb der
Grenze weitermacht.

Das ist der am stärksten getestete Teil der Codebasis: 77 Tests auf die Scope-Grenze in
[`tests/test_scope.py`](tests/test_scope.py) und 13 auf das Freigabe-Gate in
[`tests/test_consent.py`](tests/test_consent.py), von 725 insgesamt. Wenn du vor dem ersten
Einsatz gegen ein Netzwerk nur eine Sache lesen willst, lies diese.

Vorgesehener Einsatz:

- Autorisierte Penetrationstests mit schriftlicher Erlaubnis und vereinbartem Scope
- Bug-Bounty-Arbeit innerhalb der erklärten Regeln des Programms
- Dein eigenes Labor, deine eigene Hardware, CTFs
- Sicherheitsforschung an Systemen, die dir gehören

Nicht der Zweck dieses Werkzeugs und nicht vertretbar:

- Irgendetwas auf einem Host, der dir nicht gehört und für den du keine schriftliche
  Erlaubnis hast
- „Nur mal nachsehen" in einem Netzwerk, in dem du dich gerade befindest
- Alles, bei dem du nicht benennen kannst, wer es autorisiert hat

## Installation

Python **3.10+**. **nmap ist die einzige harte Voraussetzung** — alles andere schaltet
weitere Werkzeuge frei und ist optional.

```bash
curl -fsSL https://raw.githubusercontent.com/0x45dd/pwner/main/install.sh | bash
```

Das baut ein isoliertes Virtualenv unter `~/.local/share/pwner`, lässt dein System-Python
unangetastet und legt `pwner` in deinen PATH, sodass es aus jedem Verzeichnis funktioniert.
`--with-tools` installiert nmap und die optionalen Scanner mit, `--uninstall` nimmt alles
wieder heraus. Unter macOS gibt es außerdem einen Tap:

```bash
brew install 0x45dd/tap/pwner
```

Der bringt nmap mit. Aus dem Quellcode stattdessen:

```bash
git clone https://github.com/0x45dd/pwner.git
cd pwner
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
./scripts/install-deps.sh   # brew/apt/kali/pacman/dnf
pwner doctor                # was fehlt
```

**Unter Kali gibt es fast nichts zu installieren.** Ein Standard-Kali-Image bringt 8 der 11
externen Werkzeuge, die pwner fährt, schon mit. `sudo apt install nuclei bloodhound.py`
ergänzt zwei weitere, und nur kerbrute ist nicht paketiert. pwner erkennt Kali als eigenes
Ökosystem statt als Debian, deshalb gibt `pwner doctor` dir apt-Befehle statt der
Quellbuilds, die ein gewöhnliches Debian braucht. Wenn du die Wahl hast, wo du das
betreibst: dort.

## Erster Start

```bash
pwner
```

Der erste Start fragt einmal nach Provider und API-Key und speichert beides in
`~/.config/pwner/config.json` (nur für den Eigentümer lesbar). Jeder weitere Start setzt
dich direkt in eine Sitzung. Später änderbar mit `pwner --pick` (Provider/Modell-Menü), mit `pwner setup` (alle
Fragen) oder mit `/model` und `/provider` in einer laufenden Sitzung.

```bash
pwner chat 10.0.0.5          # Sitzung, Ziel gesetzt
pwner 10.0.0.0/24 --no-ai    # Sweep, ohne Modell
pwner doctor                 # Werkzeugstatus
```

In einer Sitzung sprichst du mit dem Agenten und steuerst ihn, während er arbeitet: `/help`
listet die Befehle, `/findings` und `/topology` zeigen, was er bisher aufgebaut hat, und
`/dump` schreibt das Transkript nach `~/.local/share/pwner/sessions/` (nur für den
Eigentümer — es enthält jede Zugangsinformation, die der Einsatz zutage gebracht hat, im
Klartext).

## Dein Modell

Richte es auf einen Provider und gib ihm einen Key. Presets decken OpenAI, Anthropic,
Google und DeepSeek ab; alles andere, das die OpenAI-API spricht, läuft über `--base-url`.

```bash
export PWNER_API_KEY=...
pwner chat 10.0.0.5 --provider anthropic
```

Das Modell muss Tool Calling unterstützen. `pwner chat --help` listet die Presets und jedes
Override.

### Auf deiner eigenen Hardware

`ollama` und `lemonade` sind ebenfalls Presets, und ein lokaler Endpoint braucht **keinen
API-Key** — wird einer angegeben, wird er dennoch gesendet, da Lemonade Inferenz- und
Admin-Keys trennt.

```bash
pwner chat 10.0.0.5 --provider ollama
pwner chat 10.0.0.5 --provider lemonade
```

Lokale Server heißen nach dem, was die jeweilige Maschine geladen hat, es gibt also kein
sinnvolles Standardmodell. Ist keines gesetzt, fragt pwner den `/models`-Endpoint des
Servers und nimmt, was es dort findet; `pwner setup` listet sie auf und lässt dich eines zum
Speichern auswählen. Jeder andere OpenAI-kompatible Server — llama.cpp, LM Studio, vLLM —
funktioniert genauso über `--base-url` und wird als keylos behandelt, sobald die URL auf
Loopback oder ein privates Netz zeigt.

```bash
pwner chat 10.0.0.5 --base-url http://192.168.1.50:13305/api/v1 --model Qwen3-Coder-30B
```

## Betrieb ohne Modell

`--no-ai` fährt die deterministische Suite: Host-Discovery, Portscan, Diensterkennung,
OS-Fingerprint und Erkennung bekannter Schwachstellen, danach derselbe Findings-Bericht.
Kein API-Key, keine Netzwerkaufrufe über den Scan selbst hinaus, und reproduzierbar — was es
zum Modus für CI, für einen Air-Gapped-Einsatz oder für den Fall macht, dass die Daten das
Haus nicht verlassen dürfen.

Die aktiven Werkzeuge sind die des Agenten; sie brauchen sowohl ein Modell als auch deine
Freigabe.

## Dokumentation

Die vollständige Befehls- und Konfigurationsreferenz, die Agenten-Schleife, der
Modulkatalog und die Regeln liegen auf **[pwner.si](https://www.pwner.si/)** — nur auf
Englisch:

- [Docs](https://www.pwner.si/docs) — Installation, erste Sitzung, jeder Befehl und jedes Flag
- [Agent](https://www.pwner.si/agent) — wie die Schleife arbeitet und was sie kann und nicht kann
- [Modules](https://www.pwner.si/modules) — alle 52 Werkzeuge und was jedes davon fährt
- [Rules](https://www.pwner.si/rules) — Scope, Freigabe, verantwortungsvoller Einsatz
- [Contributing](CONTRIBUTING.md) — Entwicklungsumgebung, das tools-Paket, ein Werkzeug hinzufügen
- [Security](SECURITY.md) — eine Schwachstelle in pwner selbst melden

## Kontakt

Für alles, was nicht in ein öffentliches Issue gehört — Fragen, privates Feedback oder
direkter Kontakt — schreib an [berk@planckproof.ai](mailto:berk@planckproof.ai).

Bugs und Feature-Wünsche sind als [Issue](https://github.com/0x45dd/pwner/issues) besser aufgehoben, und Sicherheitslücken
sollten über [SECURITY.md](SECURITY.md) laufen, damit sie privat bleiben, bis es einen Fix
gibt.

## Lizenz

[GNU AGPL-3.0-or-later](LICENSE). Copyright (C) 2026 Berk D.

Starkes Copyleft mit Netzwerkklausel: wenn du pwner veränderst und andere es über ein
Netzwerk nutzen lässt, schuldest du ihnen auch den veränderten Quellcode.

> [!WARNING]
> **Nur autorisierter Einsatz.** pwner sendet echten Verkehr an die Hosts, die du nennst,
> und bricht mit deiner Freigabe aktiv in sie ein. Setze es ausschließlich gegen Systeme
> ein, die dir gehören oder für die du ausdrückliche, schriftliche Erlaubnis zum Testen
> hast, und bleibe innerhalb des vereinbarten Scope. Nicht autorisiertes Testen ist in den
> meisten Rechtsordnungen strafbar.
> Diese Autorisierung zu beschaffen ist deine Verantwortung, nicht die des Werkzeugs. pwner
> wird ohne Mängelgewähr bereitgestellt, ohne Garantie und ohne Haftung für Missbrauch. Die
> Scope-Sperre und das Freigabe-Gate sind Technik, keine juristische Verteidigung.
