---
name: merge-pr-rails
description: "git worktree を使って GitHub PR を安全に取り込むワークフロー。worktree 作成・コンテナ内フルテスト・main へ rebase・レビューコメント投稿・マージ確認まで一連で実施する。「PR を取り込む」「PR をマージしたい」「依存関係の更新 PR を確認・マージしたい」「Renovate の PR をレビューしたい」などの文脈で積極的にトリガーすること。PR 番号を引数として受け取るか、引数なしでオープン PR 一覧から対話的に選択できる。"
allowed-tools: Bash
---

# PR 取り込みワークフロー (merge-pr)

このスキルは、PR を worktree で隔離してテストし、main に rebase した上でマージする安全なフローを提供する。

## 呼び出し形式

- **引数あり**: 指定された PR 番号を順に処理
- **引数なし**: `gh pr list` でオープン PR 一覧を表示し、ユーザーに選択させる

複数の PR を指定した場合は **1つずつ順番に** 処理する。次の PR に移る前に必ず main を最新化する。

---

## 環境の前提確認

作業前に以下を確認する:

```bash
# コンテナエンジンの確認
which podman && podman --version
which docker && docker --version
# GitHub CLI の確認
gh auth status
```

- **`<compose>`**: podman があれば `podman compose`、なければ `docker compose`。
  以降の例に出てくる `<compose>` はここで確定した方に置き換える
  （`<repo-name>` や `<N>` と同じくプレースホルダ）
- テストコマンド: `<compose> run --rm web bin/rails test`
- **`git push` はフックでブロックされる** → ユーザーに `! cd ...` 形式で実行を依頼する

---

## 各 PR の処理ステップ

### 作業ディレクトリの規約

2つのディレクトリを行き来する。**どちらで実行するかで結果が変わるため、常に意識する。**

- **`<repo>`** — 元のリポジトリ（例: `/mnt/development/VulnDojo-Rails`）
- **`<worktree>`** — `../<repo-name>-pr<N>`。PR の内容が反映されているのはこちら

| Step | 実行場所 |
|---|---|
| 1, 2 | `<repo>` |
| 3 | `<repo>`（worktree へは `git -C` で参照する） |
| 4 | `<worktree>` |
| 5, 5b | `<worktree>` — **ここを間違えると PR の変更が反映されていない状態でテストしてしまう** |
| 6 | ユーザーが `<worktree>` で実行 |
| 7, 8 | どちらでも可（`gh` はリポジトリ単位のため） |
| 9 | `<worktree>` で後片付け → `<repo>` へ戻ってから `worktree remove` |

git コマンドは `git -C <path>` を使えば `cd` せずに済む。`cd` が必要なのは
`<compose>` を実行する Step 5・5b・9 だけ。

### Step 1: PR の情報確認

実行場所: `<repo>`

```bash
gh pr view <N> --json headRefName,title,state,mergeable
gh pr diff <N> --name-only
gh pr view <N> --json body -q .body
```

- ブランチ名（`headRefName`）を記録する
- `state` が `OPEN`、`mergeable` が `MERGEABLE` であることを確認する。違えばここで中断してユーザーに報告する
- **変更ファイルの一覧を記録する。** Step 5 の反映操作の判定に使う
- **PR 本文に破壊的変更（breaking change）の記載があれば、それが自リポジトリに該当するか確認する**

破壊的変更の確認は、リリースノートが述べる**発火条件をコードベース上で反証する**。
条件を1つずつ潰し、該当しない根拠を示す。

```bash
# 例: ある gem がインストールされている場合のみ発火する変更
grep -nE '<gem 名>' Gemfile Gemfile.lock
# 例: 特定の API を呼んでいる場合のみ発火する変更
grep -rn '<API 名>' app/ lib/
```

該当すると判明した場合、または判断がつかない場合は、**ここで止めてユーザーに報告する**。
テストが通ることは影響がないことの証明にならない。
確認した内容と根拠は Step 7 のレビューコメントに書く。

### Step 2: worktree 作成

```bash
git fetch origin <branch>
git worktree add ../<repo-name>-pr<N> origin/<branch>
```

`<repo-name>` はカレントディレクトリのベース名（例: `VulnDojo-Rails-pr26`）。

### Step 3: rebase 要否の判定

```bash
git fetch origin
git -C ../<repo-name>-pr<N> rev-list --count HEAD..origin/main
```

この数値が 0 なら、PR ブランチは既に main 先端を含んでいる。rebase しても再生する
コミットが無く、何も起きない。コミットが書き換わらないので、後の Step 6 で push する
差分も生まれない。Step 5 へ進んでよい。

1 以上なら main が先に進んでいるので Step 4 で rebase する。rebase するとコミットの
SHA が変わるため、Step 6 で PR ブランチを同期させる必要が出てくる。

rebase の前にもテストを流すかどうかだが、通常は要らない。マージ後に main へ載るのは
rebase 後の状態なので、確かめたいのはそちらであって、テスト1回で足りる。
例外は Step 4 のコンフリクト解決が込み入って、壊したのが自分かどうかを切り分けたく
なったときで、そのときは rebase 前にも同じ準備をして走らせる（手順は Step 5 を参照）。
その切り分けで失敗が出たなら、原因をユーザーに報告して指示を仰ぐ。

### Step 4: main 先端に rebase（Step 3 の判定が 1 以上の場合のみ）

実行場所: `<worktree>`

```bash
git -C ../<repo-name>-pr<N> rebase origin/main
```

#### コンフリクト対応

**`Gemfile.lock`** は最も頻繁にコンフリクトする:
```bash
git checkout --theirs Gemfile.lock
# 必要なバージョン行（RUBY VERSION、BUNDLED WITH 等）を手動で確認・修正
git add Gemfile.lock
git rebase --continue
```

**`Gemfile`**: 両方の変更を活かして手動マージ（gem バージョン指定の競合が多い）。

**Renovate PR が Dockerfile を更新していない場合**（Ruby バージョン変更等）:
```bash
# rebase 後に Gemfile の ruby バージョンを確認
grep 'ruby "' Gemfile   # => ruby "4.0.3"
grep 'ARG RUBY_VERSION' Dockerfile   # => ARG RUBY_VERSION=3.4.9 (古いまま)

# 修正してコミット
# Edit Dockerfile の ARG RUBY_VERSION を Gemfile のバージョンに合わせる
git add Dockerfile
git commit -m "chore: update Dockerfile RUBY_VERSION to X.Y.Z"
```

### Step 5: rebase 後テスト

実行場所: `<worktree>`。ここで `cd` する。

```bash
cd ../<repo-name>-pr<N>
```

元のリポジトリで実行すると PR の変更が反映されていない状態でテストすることになり、
結果が無意味になる。

テストは、PR の変更が実際に反映された状態で走らせたい。反映されていなければ、
そのテストは変更を検証していない。緑になっても何も言えていない。

何をすれば反映されるかは、Step 1 で記録した変更ファイルから決まる。この環境では
更新が実物に届くまでにいくつか段があり、途中で止まりやすい。

Ruby の依存が変わったなら、イメージのビルドと `bundle_cache` volume の両方を新しくする。
volume はイメージ内の `/usr/local/bundle` を覆い隠すので、volume を残したまま
ビルドし直しても古い gem が使われ続ける。ビルド中に Dockerfile の `RUN bundle install`
が走るため、その後に `bundle install` を足す必要はない。

```bash
<compose> down -v          # bundle_cache を含む全ボリュームを削除
<compose> build --no-cache web
```

コンテナイメージの参照が変わったなら、取得と、動いているコンテナへの適用は別物になる。
取得しただけでは既存のコンテナは古いイメージのまま動き続ける。

アプリコードだけの変更なら volume マウントで届くので、反映のための操作は要らない。

判断がついたら、届いたことを実測で確かめてからテストに進む。gem なら
`<compose> run --rm web bundle list | grep <gem>` で版を、イメージなら digest を見る。
ここで古い版が出るなら、反映のさせ方が足りていない。

テストの出力は全文をファイルに残す。`tail` や `head` で切り詰めると、失敗した
テスト名が中間に埋もれて失われ、特定のためだけに走らせ直すことになる。

```bash
<compose> run --rm web bin/rails test > /tmp/pr<N>-test.log 2>&1
```

絞り込みは保存したログへの `grep` で行う。

**テスト失敗の場合**: 原因を調査してユーザーに報告する。rebase によるコンフリクト解決が不完全な場合は修正して再テスト。

### Step 5b: 影響機能の動作確認

テストが緑でも、更新した依存が期待どおり働いているとは限らない。テストが踏んでいない
経路は当然あるし、Step 1 で読んだ破壊的変更が本当に無関係だったかも、静的な調査だけでは
言い切れない。実際に動かして自分の目で見たものだけが根拠になる。

実行場所: `<worktree>`（Step 5 から続けて作業する）。

```bash
<compose> up -d
```

更新した依存が使われている経路を選んで通す。どこを通すかは変更内容から決まる。
csv なら CSV を吐く画面、redis ならセッションやキャッシュを跨ぐ操作、Rails 本体なら
主要な画面が出ること、Active Storage なら添付の保存と表示、といった具合に、
その依存が無ければ壊れる場所を選ぶ。Step 1 で破壊的変更を調べたなら、その影響範囲を
ここで通しておくと、静的な判断の裏が取れる。

Step 5 で volume を消していると DB が空になっている。起動しただけでは画面が出ないので、
`bin/rails db:prepare` などで用意してから触る。

ブラウザでの操作には `agent-browser` を使う（localhost には `--allow-private` が要る）。
起動ログも見ておく。例外や警告が出ていないことは、静かに壊れていないことの手がかりになる。

```bash
<compose> logs web
```

見終わったらコンテナを止める。volume は Step 9 でまとめて片付けるので、ここで消す必要はない。

```bash
<compose> down
```

ここで見た内容は Step 7 のレビューコメントに書く。何を通して何が確認できたのかが、
マージしてよいと判断した根拠になる。

### Step 6: PR ブランチの同期（Step 4 で rebase した場合）

rebase したなら、手元のブランチと GitHub 上の PR がずれている。テストして確かめたのは
手元の状態なので、レビューコメントもマージも、PR がその状態になっていることが前提になる。
ツリーの中身がたまたま同じに見えても、コミットが書き換わっている以上は同期させる。

Step 3 の判定が 0 で rebase していないなら、ずれていないのでこの Step は起きない。

`git push` はフックでブロックされるため、ユーザーに実行してもらう:

```
! cd ../<repo-name>-pr<N> && git push origin HEAD:<branch> --force-with-lease
```

反映されたことを確かめてから次へ進む。手元の HEAD と `origin/<branch>` の SHA が
一致していれば同期できている。

### Step 7: PR にレビューコメント投稿

```bash
gh pr review <N> --comment --body "..."
```

このコメントは後から読み返される記録になる。なぜマージしてよいと判断したのかが、
根拠つきで残っている状態にしたい。どの状態を基準にテストしたのか（`git log --oneline
origin/main -1` の SHA）、テストの結果、変更が妥当だと考えた理由、Step 5b で何を通して
何が見えたか、そして結論。コンフリクトを解いたり Dockerfile を直したりしたなら、
それも判断材料なので書く。rebase しなかった PR なら、rebase 済みと書く代わりに
何を基準にしたのかが分かるように書けばよい。

書く範囲はこの PR に限る。既存のフレーキーテスト、この PR と関係のない失敗、
調査の途中経過が混ざると、後から読んだ人がこの PR の問題だと誤解する。そういうものを
見つけたときはコメントに入れず、ユーザーに口頭で伝えて別に扱う。

公開される記録なので、投稿する前に本文をユーザーに見せて合意を取る。

### Step 8: マージ

マージは元に戻しにくく、main の履歴に残る。判断はユーザーのものなので、ここまでの
結果を伝えて合意を取ってから実行する。

> テスト通過・rebase 完了・レビューコメント投稿済みです。
> PR #N「<タイトル>」をマージしてよいですか？

```bash
gh pr merge <N> --merge
```

このリポジトリはブランチの履歴を残す方針なので、マージコミットを作る `--merge` を使う。
`--squash` や `--rebase` はその履歴を潰してしまう。

### Step 9: クリーンアップ

コンテナと volume は worktree 側に紐づいているので、worktree を消す前に片付ける。
ただし自分が worktree の中に立ったまま消すと、足元のディレクトリが無くなり、
以降のコマンドが `Unable to read current working directory` で動かなくなる。
片付けてから元のリポジトリへ戻り、それから消す。

```bash
cd <worktree>
<compose> down -v   # コンテナとボリュームを削除
cd <元のリポジトリディレクトリ>
git worktree remove ../<repo-name>-pr<N>
```

手元の main を進めるときは fast-forward で済ませたい。マージした PR のコミットは
既に origin/main にあるので、追いつくだけで足りる。

```bash
git fetch origin
git merge --ff-only origin/main
```

`git pull` だとこれができない。このリポジトリは `merge.ff = false` を設定していて、
fast-forward で済む場面でも `Merge branch 'main' of https://github.com/...` という
マージコミットを作る。この設定は PR のマージコミットを残してブランチの履歴を保つための
ものなので、pull が副産物として作るコミットはその意図と関係なく、履歴を読みにくくする。

既にできてしまったマージコミットには手を出さない。履歴を書き換えて消すのは、
残す方針で運用しているリポジトリでは筋が悪い。

---

## 複数 PR 処理時の注意

- PR ごとに **Step 1〜9 を完結させて** から次の PR へ進む
- 後続の PR の rebase 前に必ず main を最新化する（前の PR のマージが含まれた状態でテストするため）
- Gemfile/Gemfile.lock のコンフリクトは、先にマージされた PR の変更を取り込んだ状態で解決する

---

## レビューコメントテンプレート

```
## テスト結果

- **rebase 先**: `<SHA>` (<コミットメッセージ>)
- **テストコマンド**: `<compose> run --rm web bin/rails test`
- **結果**: ✅ 全テスト通過 (XX runs, XX assertions, 0 failures, 0 errors, 0 skips)

### 確認内容
- <変更内容の要約>
- <コンフリクト対応・追加修正があれば記載>
- main 先端に rebase 済み

### 動作確認
- <Step 5b で確認した経路と結果>

マージ可能と判断します。
```
