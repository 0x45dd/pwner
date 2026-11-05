<p align="center">
  <img src="https://raw.githubusercontent.com/0x45dd/pwner/main/docs/logo.svg" width="250" alt="pwner">
</p>

<p align="center">
  対話しながら使う、エージェント型のネットワークペネトレーションテストツール。
</p>

<p align="center">
  <a href="https://pypi.org/project/pwner/"><img
    src="https://img.shields.io/pypi/v/pwner?color=4c4a42&label=pypi"
    alt="pwner on PyPI"></a>
  <a href="https://github.com/0x45dd/pwner/blob/main/LICENSE"><img
    src="https://img.shields.io/github/license/0x45dd/pwner?color=4c4a42&label=license"
    alt="ライセンス: AGPL-3.0-or-later"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-4c4a42" alt="Python 3.10+">
</p>

<p align="center">
  <a href="https://github.com/0x45dd/pwner/blob/main/README.md">English</a> &nbsp;·&nbsp;
  <a href="https://github.com/0x45dd/pwner/blob/main/README.es.md">Español</a> &nbsp;·&nbsp;
  <a href="https://github.com/0x45dd/pwner/blob/main/README.de.md">Deutsch</a> &nbsp;·&nbsp;
  <b>日本語</b> &nbsp;·&nbsp;
  <a href="https://github.com/0x45dd/pwner/blob/main/README.tr.md">Türkçe</a>
</p>

> これは [README.md](https://github.com/0x45dd/pwner/blob/main/README.md) の要約版です。コマンドと設定の完全なリファレンスは英語のみ
> で提供されています。記述に食い違いがある場合は、英語版が正となります。

`pwner` は、ターミナルからネットワークペネトレーションテストを計画し実行する、LLM 駆動の
エージェントです。ホストを発見し、サービスをフィンガープリントで特定し、既知の問題と突き合わせ、
対象がそれに値し、かつ**あなたが承認した場合に限り**、影響を実証するために実際にエクスプロイト
します。ツールをシミュレートするのではなく実物を動かし（nmap、nuclei、netexec、impacket、
hydra など）、確認された検出結果を深刻度・証跡・修正方法とともに報告します。

自分のモデルで動きます。モデルなしでも動きます。

- **対話して使います。** フラグの羅列は不要です。*「スキャンして、データベースを重点的に」*
  と伝えれば、何を実行するかを自分で判断し、進行中の思考を見せ、途中で方針を変えさせる
  こともできます。
- **スコープはコードで強制されます。** すべてのツール呼び出しは、実行前にあなたが指定した
  対象と照合されます。プロンプトでモデルにお願いしているのではありません。
- **侵襲的な操作は既定で拒否されます。** ブルートフォース、リモートコマンド実行、
  認証情報のダンプ、リバースシェルには、あなたの明示的な承認が必要です。
- **自分のモデル、自分のマシン。** OpenAI、Anthropic、Google、DeepSeek、あるいは自分の
  ハードウェア上のサーバー（Ollama、Lemonade、llama.cpp など OpenAI 互換のすべて）。
  ローカルのエンドポイントに APIキーは不要です。あなたが設定するまで、何もどこにも
  送信されません。
- **モデルなしでも動きます。** `--no-ai` は、発見 → フィンガープリント → 検出のパイプライン
  全体を決定論的に実行します。APIキーは不要で、マシンから何も出ていきません。
- **PCI DSS セグメンテーションテスト。** `pwner pci` は対象外セグメントから CDE が分離
  されているかを検証します（11.4.5/11.4.6）。決定論的なので、修正後に再実行すれば
  11.4.4 が求める再テストになります。これ自体が準拠を与えるものではありません。
- **52 のツール。** nmap、HTTP、サービス別のプローブ、Active Directory、認証情報関連。
  いずれも標準バイナリの薄いラッパーであり、再実装ではありません。

## 安全性のモデル

2 つの仕組みがあり、どちらもツール層にあり、どちらもモデルの手の届かないところにあります。

**スコープロック。** [`build_dispatch`](https://github.com/0x45dd/pwner/blob/main/pwner/tools/core.py) がすべてのツールをラップし、
ホストを含む引数は、ツール本体が実行される*前*にあなたの対象と照合されます。ツールは既定で
スコープ内として扱われるため、自前のチェックを忘れたツールも保護され、未登録のツール名は
安全側に倒れて失敗します。ネットワーク引数は、認可範囲に完全に収まっていなければなりません。

ガードが検査できない唯一のものが `set_target` です。その引数が新しいスコープそのものだから
です。代わりに独自のゲートを持ちます。狭めるのは自由ですが、すでに許可した範囲の外へ移るには
毎回あなたの回答が必要で、`--auto-consent` はこれを含みません。

**承認ゲート。** 能動的な操作は、そのセッションであなたが承認しない限りすべて拒否されます。
承認はモデルの外側で解決されるため、エージェントが自分で承認することはできません。非対話的な
実行では、`--auto-consent` を付けて起動した場合を除き、拒否されます。

拒否は実行を止めるエラーではありません。ツールの結果としてモデルに返されるので、エージェントは
行き過ぎたことを学び、境界の内側で作業を続けます。

ここはコードベースの中で最もテストが厚い部分です。スコープ境界に
[`tests/test_scope.py`](https://github.com/0x45dd/pwner/blob/main/tests/test_scope.py) の 77 件、承認ゲートに
[`tests/test_consent.py`](https://github.com/0x45dd/pwner/blob/main/tests/test_consent.py) の 13 件、全体 725 件のうちの内訳です。
これをネットワークに向ける前に 1 つだけ読むなら、この 2 つを読んでください。

想定している用途:

- 書面による許可と合意されたスコープのもとで行う、認可されたペネトレーションテスト
- プログラムが明示した規則の範囲内でのバグバウンティ
- 自分のラボ、自分のハードウェア、CTF
- 自分が所有するシステムに対するセキュリティ研究

このツールの目的ではなく、正当化もできないこと:

- 自分の所有物でなく、テストの書面による許可もないホストに対する一切の行為
- たまたま接続しているネットワークを「ちょっと見てみる」こと
- 誰が認可したのかを言えない一切の行為

## インストール

Python **3.10 以上**。**必須の依存は nmap だけ**です。それ以外はツールを増やすための
任意の依存です。

```bash
curl -fsSL https://raw.githubusercontent.com/0x45dd/pwner/main/install.sh | bash
```

これは `~/.local/share/pwner` 以下に独立した virtualenv を作り、システムの Python には
手を付けず、`pwner` を PATH に置くのでどのディレクトリからでも動きます。`--with-tools` を
付けると nmap と任意のスキャナも入り、`--uninstall` ですべて取り除けます。

PyPI にも公開しているので、普段使いの Python ツールからも入れられます。

```bash
pipx install pwner      # 独立環境に入り、`pwner` が PATH に置かれる
uv tool install pwner   # 同じことを uv で
pip install pwner       # virtualenv の中で
```

素の `pip install` より `pipx` か `uv tool` を選んでください。インストールスクリプトと同じ
独立性が得られますし、そもそもシステムの Python へのインストールは最近のディストリビュー
ションではまず拒否されます。

macOS 向けには tap もあります。

```bash
brew install 0x45dd/tap/pwner
```

こちらは nmap も一緒に入ります。ソースから入れる場合:

```bash
git clone https://github.com/0x45dd/pwner.git
cd pwner
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
./scripts/install-deps.sh   # brew/apt/kali/pacman/dnf
pwner doctor                # 不足しているものを表示
```

**Kali ならインストールするものはほとんどありません。** 既定の Kali イメージには、pwner が
動かす 11 個の外部ツールのうち 8 個が最初から入っています。`sudo apt install nuclei
bloodhound.py` でさらに 2 個が加わり、パッケージ化されていないのは kerbrute だけです。
pwner は Kali を Debian ではなく独立したエコシステムとして認識するため、`pwner doctor` は
素の Debian で必要になるソースビルドではなく apt コマンドを提示します。どこで動かすか選べる
なら、Kali で動かしてください。

## 最初の起動

```bash
pwner
```

最初の起動でプロバイダと APIキーを一度だけ尋ね、`~/.config/pwner/config.json` に保存します
（所有者のみ読み取り可）。以降の起動では、そのままセッションに入ります。あとから変更するには
`pwner --pick`（プロバイダ/モデルの一覧から選ぶ）、`pwner setup`（最初からすべて聞く）、
あるいは実行中のセッション内で `/model` と `/provider` を使います。

```bash
pwner chat 10.0.0.5          # セッション、対象を設定済み
pwner 10.0.0.0/24 --no-ai    # スイープ、モデルなし
pwner doctor                 # ツールの状態
```

セッション中はエージェントと対話し、作業中に方向を指示できます。`/help` でコマンド一覧、
`/findings` と `/topology` でそれまでに組み上げた内容を表示、`/dump` で記録を
`~/.local/share/pwner/sessions/` に書き出します（所有者のみ読み取り可。作業で判明した
認証情報がすべて平文で含まれます）。

## モデルの設定

プロバイダを指定してキーを渡します。プリセットは OpenAI、Anthropic、Google、DeepSeek を
カバーし、OpenAI API を話すものであれば `--base-url` で動きます。

```bash
export PWNER_API_KEY=...
pwner chat 10.0.0.5 --provider anthropic
```

モデルはツール呼び出し（tool calling）に対応している必要があります。`pwner chat --help` に
プリセットとすべての上書きオプションが並びます。

### 自分のハードウェア上で

`ollama` と `lemonade` もプリセットで、ローカルのエンドポイントに **APIキーは不要**です。
与えた場合は送信されます。Lemonade が推論用と管理用のキーを分けているためです。

```bash
pwner chat 10.0.0.5 --provider ollama
pwner chat 10.0.0.5 --provider lemonade
```

ローカルサーバーのモデル名はそのマシンが取得したものに依存するため、妥当な既定値がありません。
指定がない場合、pwner はサーバーの `/models` エンドポイントに問い合わせ、見つかったものを
使います。`pwner setup` は一覧を表示し、保存するものを選ばせます。他の OpenAI 互換サーバー
（llama.cpp、LM Studio、vLLM）も `--base-url` で同じように動き、URL がループバックまたは
プライベートネットワークを指している場合はキー不要として扱われます。

```bash
pwner chat 10.0.0.5 --base-url http://192.168.1.50:13305/api/v1 --model Qwen3-Coder-30B
```

## モデルなしで実行する

`--no-ai` は決定論的な一連の処理を実行します。ホスト発見、ポートスキャン、サービス検出、
OS フィンガープリント、既知の問題の検出、そして同じ検出結果レポートです。APIキーは不要、
スキャン自体を超えるネットワーク通信はなく、再現可能です。そのため CI、エアギャップ環境での
作業、あるいはデータを外に出せない場合に使うモードになります。

能動的なツールはエージェントのものであり、モデルとあなたの承認の両方が必要です。

## ドキュメント

コマンドと設定の完全なリファレンス、エージェントのループ、モジュール一覧、規約は
**[pwner.si](https://www.pwner.si/)** にあります（英語のみ）。

- [Docs](https://www.pwner.si/docs) — インストール、最初のセッション、全コマンドとフラグ
- [Agent](https://www.pwner.si/agent) — ループの仕組みと、できること・できないこと
- [Modules](https://www.pwner.si/modules) — 52 個のツールと、それぞれが何を動かすか
- [Rules](https://www.pwner.si/rules) — スコープ、承認、責任ある利用
- [Contributing](https://github.com/0x45dd/pwner/blob/main/CONTRIBUTING.md) — 開発環境、tools パッケージ、ツールの追加方法
- [Security](https://github.com/0x45dd/pwner/blob/main/SECURITY.md) — pwner 自体の脆弱性の報告

## 連絡先

公開の issue に向かないこと（質問、非公開のフィードバック、直接の連絡）は
[berk@planckproof.ai](mailto:berk@planckproof.ai) までメールしてください。

バグや機能の要望は [issue](https://github.com/0x45dd/pwner/issues) のほうが適しています。脆弱性については、修正ができるまで
非公開に保てるよう [SECURITY.md](https://github.com/0x45dd/pwner/blob/main/SECURITY.md) の手順に従ってください。

## ライセンス

[GNU AGPL-3.0-or-later](https://github.com/0x45dd/pwner/blob/main/LICENSE)。Copyright (C) 2026 Berk D.

ネットワーク条項を含む強いコピーレフトです。pwner を改変し、ネットワーク越しに他の人に
使わせる場合、改変したソースもその人たちに提供する義務があります。

> [!WARNING]
> **許可された用途のみ。** pwner はあなたが指定したホストに実際のトラフィックを送信し、
> あなたの承認があれば能動的に侵入します。自分が所有するシステム、またはテストについて
> 明示的な書面による許可を得ているシステムに対してのみ実行し、合意されたスコープの内側に
> とどめてください。認可のないテストは、ほとんどの法域で違法です。
> その認可を取得するのはツールではなくあなたの責任です。pwner は現状のまま提供され、
> いかなる保証もなく、誤用に対する責任も負いません。スコープロックと承認ゲートは
> エンジニアリング上の仕組みであり、法的な抗弁にはなりません。
