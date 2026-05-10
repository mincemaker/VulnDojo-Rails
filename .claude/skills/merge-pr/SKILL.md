---
name: merge-pr
description: "git worktree を使って GitHub PR を安全に取り込むワークフロー。worktree 作成・コンテナ内フルテスト・main へ rebase・レビューコメント投稿・マージ確認まで一連で実施する。「PR を取り込む」「PR をマージしたい」「依存関係の更新 PR を確認・マージしたい」「Renovate の PR をレビューしたい」などの文脈で積極的にトリガーすること。PR 番号を引数として受け取るか、引数なしでオープン PR 一覧から対話的に選択できる。"
allowed-tools: Bash
---

# PR 取り込みワークフロー (merge-pr)

このスキルは、PR を worktree で隔離してテストし、main に rebase した上でマージする安全なフローを提供する。

## 呼び出し形式

- **引数あり**: 指定された PR 番号を順に処理
- **引数なし**: `rtk gh pr list` でオープン PR 一覧を表示し、ユーザーに選択させる

複数の PR を指定した場合は **1つずつ順番に** 処理する。次の PR に移る前に必ず main を最新化する。

---

## 環境の前提確認

作業前に以下を確認する:

```bash
# コンテナエンジンの確認
which docker && docker --version   # podman がなければ docker を使う
# RTK の確認
which rtk
# GitHub CLI の確認
gh auth status
```

- テストコマンド: `docker compose run --rm web bin/rails test`
- **`git push` はフックでブロックされる** → ユーザーに `! cd ...` 形式で実行を依頼する

---

## 各 PR の処理ステップ

### Step 1: PR の情報確認

```bash
rtk gh pr view <N> --json headRefName,title,state,mergeable
```

ブランチ名（`headRefName`）を記録する。

### Step 2: worktree 作成

```bash
rtk git fetch origin <branch>
rtk git worktree add ../<repo-name>-pr<N> origin/<branch>
```

`<repo-name>` はカレントディレクトリのベース名（例: `VulnDojo-Rails-pr26`）。

### Step 3: テスト実行（rebase 前）

worktree ディレクトリに移動して実行:

```bash
cd ../<repo-name>-pr<N>
docker compose run --rm web bin/rails test
```

**テスト失敗の場合**: 結果をユーザーに報告し、このPRの処理を中断する。次の PR があれば続行するか確認する。

### Step 4: main 先端に rebase

```bash
rtk git fetch origin
rtk git rebase origin/main
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

**Ruby/bundler バージョンが変わった場合**、古い bundle_cache volume が残っていると gem not found エラーが出る。その場合は:

```bash
docker compose down -v   # bundle_cache を含む全ボリュームを削除
```

テストを実行:

```bash
docker compose run --rm web bin/rails test
```

**テスト失敗の場合**: 原因を調査してユーザーに報告する。rebase によるコンフリクト解決が不完全な場合は修正して再テスト。

### Step 6: ユーザーに push を依頼

`git push` はフックでブロックされるため、以下をユーザーに実行してもらう:

```
! cd ../<repo-name>-pr<N> && rtk git push origin HEAD:<branch> --force-with-lease
```

push が完了したことを確認してから次のステップへ進む。

### Step 7: PR にレビューコメント投稿

```bash
gh pr review <N> --comment --body "..."
```

コメントに必ず含める内容:
- **rebase 先**: main 先端の SHA とコミットメッセージ（`rtk git log --oneline origin/main -1`）
- **テスト結果**: `XX runs, XX assertions, 0 failures, 0 errors, 0 skips`
- **確認内容**: 変更の妥当性、コンフリクト対応内容、Dockerfile 修正等
- **判定**: 「マージ可能と判断します。」または問題がある場合はその内容

### Step 8: マージ（ユーザー確認必須）

レビューコメント投稿後、**必ずユーザーに確認を求める**:

> テスト通過・rebase 完了・レビューコメント投稿済みです。
> PR #N「<タイトル>」をマージしてよいですか？

ユーザーが承認したら:

```bash
gh pr merge <N> --merge
```

### Step 9: クリーンアップ

```bash
cd <元のリポジトリディレクトリ>
rtk git worktree remove ../<repo-name>-pr<N>
rtk git pull origin main
```

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
- **テストコマンド**: `docker compose run --rm web bin/rails test`
- **結果**: ✅ 全テスト通過 (XX runs, XX assertions, 0 failures, 0 errors, 0 skips)

### 確認内容
- <変更内容の要約>
- <コンフリクト対応・追加修正があれば記載>
- main 先端に rebase 済み

マージ可能と判断します。
```
