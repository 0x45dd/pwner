<p align="center">
  <img src="docs/logo.svg" width="250" alt="pwner">
</p>

<p align="center">
  Una herramienta agéntica de pentesting de red con la que hablas.
</p>

<p align="center">
  <a href="LICENSE"><img
    src="https://img.shields.io/github/license/0x45dd/pwner?color=4c4a42&label=license"
    alt="Licencia: AGPL-3.0-or-later"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-4c4a42" alt="Python 3.10+">
</p>

<p align="center">
  <a href="README.md">English</a> &nbsp;·&nbsp;
  <b>Español</b> &nbsp;·&nbsp;
  <a href="README.de.md">Deutsch</a> &nbsp;·&nbsp;
  <a href="README.ja.md">日本語</a> &nbsp;·&nbsp;
  <a href="README.tr.md">Türkçe</a>
</p>

> Esta es una traducción resumida de [README.md](README.md). La referencia completa de
> comandos y configuración solo existe en inglés. Si encuentras una discrepancia, el texto
> en inglés es el que manda.

`pwner` es un agente dirigido por un LLM que planifica y ejecuta un test de penetración de
red desde tu terminal. Descubre hosts, identifica servicios, los comprueba contra problemas
conocidos y —cuando el objetivo lo justifica y **tú** lo apruebas— los explota para
demostrar el impacto. Ejecuta herramientas reales (nmap, nuclei, netexec, impacket, hydra y
otras) en lugar de simularlas, y reporta hallazgos confirmados con severidad, evidencia y
solución.

Funciona con tu propio modelo, o sin modelo alguno.

- **Hablas con ella.** Sin sopa de flags: dices *"escanéalo, céntrate en la base de
  datos"* y decide qué ejecutar, te muestra su razonamiento mientras avanza, y puedes
  redirigirla a mitad de ejecución.
- **El alcance se aplica en código.** Cada llamada a una herramienta se verifica contra el
  objetivo que indicaste antes de ejecutarse, no se le pide al modelo en un prompt.
- **Las acciones intrusivas se deniegan por defecto.** La fuerza bruta, la ejecución remota
  de comandos, el volcado de credenciales y las reverse shell requieren tu aprobación
  explícita.
- **Tu modelo, tu máquina.** OpenAI, Anthropic, Google, DeepSeek o un servidor en tu propio
  hardware: Ollama, Lemonade, llama.cpp, cualquier cosa compatible con la API de OpenAI. Un
  endpoint local no necesita API key. Nada sale de tu máquina hasta que tú lo configures.
- **Funciona sin modelo.** `--no-ai` ejecuta todo el pipeline de descubrimiento →
  identificación → detección de forma determinista, sin API key y sin que nada salga de la
  máquina.
- **47 herramientas** entre nmap, HTTP, sondas por servicio, Active Directory y trabajo con
  credenciales, cada una un envoltorio fino sobre el binario estándar, no una
  reimplementación.

## Modelo de seguridad

Dos mecanismos, ambos en la capa de herramientas, ambos fuera del alcance del modelo.

**Bloqueo de alcance.** [`build_dispatch`](pwner/tools/core.py) envuelve cada herramienta
para que todo argumento que lleve un host se verifique contra tu objetivo *antes* de que se
ejecute el cuerpo de la herramienta. Las herramientas están dentro del alcance por defecto:
una que olvide su propia comprobación sigue estando protegida, y un nombre de herramienta no
registrado falla de forma cerrada. Un argumento de red tiene que caber por completo dentro
de la autorización.

**Puerta de consentimiento.** Todo lo activo se deniega salvo que lo apruebes en esa sesión.
El consentimiento se resuelve fuera del modelo —el agente no puede aprobarse a sí mismo— y
en una ejecución no interactiva la respuesta es siempre no.

Una denegación no es un error que detenga la ejecución: vuelve al modelo como resultado de
la herramienta, así que el agente aprende que se excedió y continúa dentro del límite.

Esta es la parte del código con más pruebas: 77 pruebas sobre el límite de alcance en
[`tests/test_scope.py`](tests/test_scope.py) y 13 sobre la puerta de consentimiento en
[`tests/test_consent.py`](tests/test_consent.py), de 532 en total. Si vas a leer una sola
cosa antes de apuntar esto a una red, lee esas.

Uso previsto:

- Tests de penetración autorizados, con permiso por escrito y un alcance acordado
- Trabajo de bug bounty, dentro de las reglas declaradas del programa
- Tu propio laboratorio, tu propio hardware, CTFs
- Investigación de seguridad sobre sistemas de tu propiedad

Lo que no es el propósito de esta herramienta, y no es defendible:

- Cualquier cosa sobre un host que no sea tuyo y para el que no tengas permiso escrito
- "Solo echar un vistazo" a una red en la que te encuentras
- Cualquier cosa en la que no puedas decir quién la autorizó

## Instalación

Python **3.10+**. **nmap es el único requisito obligatorio**; todo lo demás habilita más
herramientas y es opcional.

```bash
curl -fsSL https://raw.githubusercontent.com/0x45dd/pwner/main/install.sh | bash
```

Eso construye un virtualenv aislado en `~/.local/share/pwner`, deja en paz el Python del
sistema y pone `pwner` en tu PATH para que funcione desde cualquier directorio. Añade
`--with-tools` para instalar también nmap y los escáneres opcionales, y `--uninstall` para
quitarlo todo. En macOS también hay un tap:

```bash
brew install 0x45dd/tap/pwner
```

Eso trae nmap consigo. Desde el código fuente:

```bash
git clone https://github.com/0x45dd/pwner.git
cd pwner
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
./scripts/install-deps.sh   # brew/apt/kali/pacman/dnf
pwner doctor                # qué falta
```

**En Kali no hay casi nada que instalar.** Una imagen de Kali por defecto ya trae 8 de las
11 herramientas externas que pwner usa. `sudo apt install nuclei bloodhound.py` añade dos
más, y la única sin empaquetar es kerbrute. pwner detecta Kali como su propio ecosistema en
lugar de como Debian, así que `pwner doctor` te da comandos de apt en vez de las
compilaciones desde fuente que necesita un Debian normal. Si estás eligiendo dónde ejecutar
esto, ejecútalo ahí.

## Primera ejecución

```bash
pwner
```

La primera ejecución pide un proveedor y una API key una sola vez, y los guarda en
`~/.config/pwner/config.json` (solo lectura para el propietario). Cada ejecución posterior
te deja directamente en una sesión. Cámbialo después con `pwner setup`.

```bash
pwner chat 10.0.0.5          # sesión, objetivo fijado
pwner 10.0.0.0/24 --no-ai    # barrido, sin modelo
pwner doctor                 # estado de las herramientas
```

Dentro de una sesión hablas con el agente y lo guías mientras trabaja: `/help` lista los
comandos, `/findings` y `/topology` muestran lo que ha construido hasta ahora, y `/dump`
escribe la transcripción en `~/.local/share/pwner/sessions/` (solo para el propietario:
contiene en texto claro todas las credenciales que haya encontrado el trabajo).

## Tu modelo

Apúntalo a un proveedor y dale una key. Los presets cubren OpenAI, Anthropic, Google y
DeepSeek; cualquier otra cosa que hable la API de OpenAI funciona con `--base-url`.

```bash
export PWNER_API_KEY=...
pwner chat 10.0.0.5 --provider anthropic
```

El modelo tiene que soportar tool calling. `pwner chat --help` lista los presets y todas las
opciones de sobrescritura.

### En tu propio hardware

`ollama` y `lemonade` también son presets, y un endpoint local **no necesita API key**: si
se le da una, se envía igualmente, ya que Lemonade separa las keys de inferencia de las de
administración.

```bash
pwner chat 10.0.0.5 --provider ollama
pwner chat 10.0.0.5 --provider lemonade
```

Los servidores locales se nombran según lo que esa máquina haya descargado, así que no hay
un modelo por defecto razonable. Cuando no se fija ninguno, pwner consulta el endpoint
`/models` del servidor y usa lo que encuentra; `pwner setup` los lista y te deja elegir uno
para guardarlo. Cualquier otro servidor compatible con OpenAI —llama.cpp, LM Studio, vLLM—
funciona igual con `--base-url`, y se trata como sin key siempre que la URL apunte a
loopback o a una red privada.

```bash
pwner chat 10.0.0.5 --base-url http://192.168.1.50:13305/api/v1 --model Qwen3-Coder-30B
```

## Ejecutar sin modelo

`--no-ai` ejecuta la suite determinista: descubrimiento de hosts, escaneo de puertos,
detección de servicios, identificación del SO y detección de problemas conocidos, y después
el mismo informe de hallazgos. Sin API key, sin llamadas de red más allá del propio escaneo,
y reproducible, lo que lo convierte en el modo a usar en CI, en un trabajo air-gapped o
cuando los datos no pueden salir del edificio.

Las herramientas activas son las del agente: necesitan tanto un modelo como tu
consentimiento.

## Documentación

La referencia completa de comandos y configuración, el bucle del agente, el catálogo de
módulos y las reglas están en **[pwner.si](https://www.pwner.si/)**, solo en inglés:

- [Docs](https://www.pwner.si/docs) — instalación, primera sesión, cada comando y flag
- [Agent](https://www.pwner.si/agent) — cómo funciona el bucle y qué puede y no puede hacer
- [Modules](https://www.pwner.si/modules) — las 47 herramientas y qué usa cada una
- [Rules](https://www.pwner.si/rules) — alcance, consentimiento, uso responsable
- [Contributing](CONTRIBUTING.md) — entorno de desarrollo, el paquete tools, añadir una herramienta
- [Security](SECURITY.md) — reportar una vulnerabilidad en pwner mismo

## Contacto

Para cualquier cosa que no encaje en un issue público —preguntas, comentarios privados o
simplemente ponerse en contacto directamente— escribe a [berk@planckproof.ai](mailto:berk@planckproof.ai).

Los bugs y las peticiones de funcionalidad funcionan mejor como [issues](https://github.com/0x45dd/pwner/issues), y las
vulnerabilidades de seguridad deberían ir por [SECURITY.md](SECURITY.md) para que sigan
siendo privadas hasta que haya una corrección.

## Licencia

[GNU AGPL-3.0-or-later](LICENSE). Copyright (C) 2026 Berk D.

Copyleft fuerte, con cláusula de red: si modificas pwner y dejas que otras personas lo usen
a través de una red, también les debes el código fuente modificado.

> [!WARNING]
> **Solo uso autorizado.** pwner envía tráfico real a los hosts que indiques y, con tu
> aprobación, entra activamente en ellos. Ejecútalo únicamente contra sistemas de tu
> propiedad o para los que tengas permiso explícito y por escrito, y mantente dentro del
> alcance acordado. El testing no autorizado es ilegal en la mayoría de las jurisdicciones.
> Obtener esa autorización es tu responsabilidad, no la de la herramienta. pwner se
> proporciona tal cual, sin garantía y sin responsabilidad por mal uso. El bloqueo de
> alcance y la puerta de consentimiento son ingeniería, no una defensa legal.
