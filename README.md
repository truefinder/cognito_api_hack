# cognito_api_hack

AWS Cognito Identity Provider Serviceのユーザー向け機能をコマンドラインから操作するためのPythonツールです。

## 機能

- ユーザー情報の取得・更新
- ユーザー属性の管理（追加・更新・削除・検証）
- MFA（多要素認証）の設定
  - SMS MFA
  - TOTP MFA（QRコード生成対応）
- デバイス管理
  - デバイス一覧表示
  - デバイス情報取得
  - デバイスステータス更新
  - デバイス削除
- セッション管理
  - グローバルサインアウト
  - トークン無効化
- アカウント管理
  - パスワード変更
  - アカウント削除

## 必要条件

- Python 3.x
- 以下のPythonパッケージ:
  ```
  boto3
  qrcode[pil]
  pyotp
  argparse
  ```

## インストール

```bash
pip install boto3 qrcode[pil] pyotp argparse
```

## 使用方法

基本的な使い方:

```bash
python cognito_api_hack.py --token YOUR_TOKEN --region us-west-2 [command] [options]
```

### 主なコマンド例

1. ユーザー情報取得:
```bash
python cognito_api_hack.py --token YOUR_TOKEN get-user
```

2. ユーザー属性更新:
```bash
python cognito_api_hack.py --token YOUR_TOKEN update-attributes --given-name 太郎 --family-name 山田
```

3. MFA設定:
```bash
python cognito_api_hack.py --token YOUR_TOKEN set-mfa --totp-enabled --totp-preferred
```

4. デバイス一覧表示:
```bash
python cognito_api_hack.py --token YOUR_TOKEN list-devices
```

### 詳細なヘルプ

```bash
python cognito_api_hack.py --help
```

## 出力形式

- デフォルトでは人間が読みやすい形式で出力
- `--json` オプションでJSON形式の出力が可能

## セキュリティ注意事項

- アクセストークンは必ず安全に管理してください
- 重要な操作（アカウント削除など）には確認プロンプトがあります
- トークンの有効期限に注意してください

## ライセンス

Apache License Version 2.0

このプロジェクトは[Apache License Version 2.0](LICENSE)の下で提供されています。

## 注意事項

- このツールは aws.cognito.signin.user.admin スコープで利用可能な機能のみをサポートしています
- 本番環境で使用する前に十分なテストを行ってください

