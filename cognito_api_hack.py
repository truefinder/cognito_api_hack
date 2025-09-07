#!/usr/bin/env python3
"""
AWS Cognito Identity Provider Service CLI Client
aws.cognito.signin.user.admin スコープで使用可能な全ての機能をコマンドラインから実行

Requirements:
pip install boto3 qrcode[pil] pyotp argparse

Usage:
python cognito_client.py --help
python cognito_client.py --token YOUR_TOKEN --region us-west-2 get-user
python cognito_client.py --token YOUR_TOKEN update-attributes --given-name John --family-name Doe
"""

import boto3
import json
import argparse
import sys
import os
import qrcode
import pyotp
from typing import Dict, List, Optional, Any
from botocore.exceptions import ClientError


class CognitoUserClient:
    """
    AWS Cognito Identity Provider Service のユーザー向けクライアント
    """
    
    def __init__(self, region: str = 'us-west-2', access_token: str = None):
        self.region = region
        self.access_token = access_token
        self.client = boto3.client('cognito-idp', region_name=region)
        
    def set_access_token(self, access_token: str):
        self.access_token = access_token
    
    def _handle_error(self, func_name: str, error: ClientError) -> Dict[str, Any]:
        error_code = error.response['Error']['Code']
        error_message = error.response['Error']['Message']
        print(f"❌ {func_name} エラー: {error_code} - {error_message}")
        return {
            'success': False,
            'error_code': error_code,
            'error_message': error_message
        }
    
    def get_user(self) -> Dict[str, Any]:
        """現在のユーザー情報を取得"""
        try:
            response = self.client.get_user(AccessToken=self.access_token)
            print("✅ ユーザー情報取得成功")
            print(f"ユーザー名: {response['Username']}")
            print("ユーザー属性:")
            for attr in response['UserAttributes']:
                print(f"  {attr['Name']}: {attr['Value']}")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('get_user', e)
    
    def update_user_attributes(self, attributes: Dict[str, str]) -> Dict[str, Any]:
        """ユーザー属性を更新"""
        try:
            user_attributes = [
                {'Name': name, 'Value': value} 
                for name, value in attributes.items()
            ]
            
            response = self.client.update_user_attributes(
                AccessToken=self.access_token,
                UserAttributes=user_attributes
            )
            print(f"✅ ユーザー属性更新成功: {list(attributes.keys())}")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('update_user_attributes', e)
    
    def delete_user_attributes(self, attribute_names: List[str]) -> Dict[str, Any]:
        """ユーザー属性を削除"""
        try:
            response = self.client.delete_user_attributes(
                AccessToken=self.access_token,
                UserAttributeNames=attribute_names
            )
            print(f"✅ ユーザー属性削除成功: {attribute_names}")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('delete_user_attributes', e)
    
    def get_user_attribute_verification_code(self, attribute_name: str) -> Dict[str, Any]:
        """属性検証コードを要求"""
        try:
            response = self.client.get_user_attribute_verification_code(
                AccessToken=self.access_token,
                AttributeName=attribute_name
            )
            print(f"✅ {attribute_name} 検証コード送信成功")
            if 'DeliveryDetails' in response:
                delivery = response['DeliveryDetails']
                print(f"配信方法: {delivery.get('DeliveryMedium', 'N/A')}")
                print(f"配信先: {delivery.get('Destination', 'N/A')}")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('get_user_attribute_verification_code', e)
    
    def verify_user_attribute(self, attribute_name: str, code: str) -> Dict[str, Any]:
        """ユーザー属性を検証"""
        try:
            response = self.client.verify_user_attribute(
                AccessToken=self.access_token,
                AttributeName=attribute_name,
                Code=code
            )
            print(f"✅ {attribute_name} 属性検証成功")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('verify_user_attribute', e)
    
    def change_password(self, previous_password: str, proposed_password: str) -> Dict[str, Any]:
        """パスワードを変更"""
        try:
            response = self.client.change_password(
                AccessToken=self.access_token,
                PreviousPassword=previous_password,
                ProposedPassword=proposed_password
            )
            print("✅ パスワード変更成功")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('change_password', e)
    
    def set_user_mfa_preference(self, 
                               sms_enabled: bool = False, 
                               sms_preferred: bool = False,
                               totp_enabled: bool = False,
                               totp_preferred: bool = False) -> Dict[str, Any]:
        """MFA設定を管理"""
        try:
            response = self.client.set_user_mfa_preference(
                AccessToken=self.access_token,
                SMSMfaSettings={
                    'Enabled': sms_enabled,
                    'PreferredMfa': sms_preferred
                },
                SoftwareTokenMfaSettings={
                    'Enabled': totp_enabled,
                    'PreferredMfa': totp_preferred
                }
            )
            print("✅ MFA設定更新成功")
            print(f"SMS MFA: {'有効' if sms_enabled else '無効'}")
            print(f"TOTP MFA: {'有効' if totp_enabled else '無効'}")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('set_user_mfa_preference', e)
    
    def associate_software_token(self) -> Dict[str, Any]:
        """TOTP ソフトウェアトークンを関連付け"""
        try:
            response = self.client.associate_software_token(
                AccessToken=self.access_token
            )
            
            secret_code = response.get('SecretCode', '')
            print("✅ ソフトウェアトークン関連付け成功")
            print(f"シークレットコード: {secret_code}")
            
            # QRコード生成
            if secret_code:
                self._generate_totp_qr_code(secret_code)
            
            return {'success': True, 'data': response, 'secret_code': secret_code}
        except ClientError as e:
            return self._handle_error('associate_software_token', e)
    
    def verify_software_token(self, user_code: str, 
                            friendly_device_name: str = "Python CLI") -> Dict[str, Any]:
        """ソフトウェアトークンを検証"""
        try:
            response = self.client.verify_software_token(
                AccessToken=self.access_token,
                UserCode=user_code,
                FriendlyDeviceName=friendly_device_name
            )
            
            status = response.get('Status', 'UNKNOWN')
            print(f"✅ ソフトウェアトークン検証: {status}")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('verify_software_token', e)
    
    def _generate_totp_qr_code(self, secret_code: str, username: str = "user"):
        """TOTP用のQRコードを生成"""
        try:
            totp_uri = f"otpauth://totp/CognitoApp:{username}?secret={secret_code}&issuer=CognitoApp"
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            img.save("totp_qr_code.png")
            print("📱 QRコードを 'totp_qr_code.png' に保存しました")
            print(f"または手動でシークレットコードを入力: {secret_code}")
        except Exception as e:
            print(f"⚠️ QRコード生成エラー: {e}")
    
    def list_devices(self, limit: int = 10) -> Dict[str, Any]:
        """登録されたデバイス一覧を取得"""
        try:
            response = self.client.list_devices(
                AccessToken=self.access_token,
                Limit=limit
            )
            
            devices = response.get('Devices', [])
            print(f"✅ デバイス一覧取得成功 ({len(devices)}件)")
            
            for i, device in enumerate(devices, 1):
                print(f"{i}. デバイスキー: {device['DeviceKey']}")
                print(f"   作成日: {device['DeviceCreateDate']}")
                print(f"   最終更新: {device['DeviceLastModifiedDate']}")
                if 'DeviceAttributes' in device:
                    for attr in device['DeviceAttributes']:
                        print(f"   {attr['Name']}: {attr['Value']}")
                print()
            
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('list_devices', e)
    
    def get_device(self, device_key: str) -> Dict[str, Any]:
        """特定のデバイス情報を取得"""
        try:
            response = self.client.get_device(
                AccessToken=self.access_token,
                DeviceKey=device_key
            )
            
            device = response.get('Device', {})
            print(f"✅ デバイス情報取得成功: {device_key}")
            print(f"作成日: {device.get('DeviceCreateDate', 'N/A')}")
            print(f"最終更新: {device.get('DeviceLastModifiedDate', 'N/A')}")
            
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('get_device', e)
    
    def update_device_status(self, device_key: str, 
                           status: str = "remembered") -> Dict[str, Any]:
        """デバイスのステータスを更新"""
        try:
            response = self.client.update_device_status(
                AccessToken=self.access_token,
                DeviceKey=device_key,
                DeviceRememberedStatus=status
            )
            print(f"✅ デバイスステータス更新成功: {device_key} -> {status}")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('update_device_status', e)
    
    def forget_device(self, device_key: str) -> Dict[str, Any]:
        """デバイスを削除"""
        try:
            response = self.client.forget_device(
                AccessToken=self.access_token,
                DeviceKey=device_key
            )
            print(f"✅ デバイス削除成功: {device_key}")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('forget_device', e)
    
    def global_sign_out(self) -> Dict[str, Any]:
        """全てのデバイスからログアウト"""
        try:
            response = self.client.global_sign_out(
                AccessToken=self.access_token
            )
            print("✅ グローバルサインアウト成功")
            print("⚠️ このアクセストークンは無効になりました")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('global_sign_out', e)
    
    def revoke_token(self, refresh_token: str, client_id: str) -> Dict[str, Any]:
        """トークンを無効化"""
        try:
            response = self.client.revoke_token(
                Token=refresh_token,
                ClientId=client_id
            )
            print("✅ トークン無効化成功")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('revoke_token', e)
    
    def delete_user(self) -> Dict[str, Any]:
        """自分のアカウントを削除"""
        try:
            response = self.client.delete_user(
                AccessToken=self.access_token
            )
            print("✅ ユーザーアカウント削除成功")
            print("⚠️ アカウントは完全に削除されました")
            return {'success': True, 'data': response}
        except ClientError as e:
            return self._handle_error('delete_user', e)


def create_parser():
    """コマンドライン引数パーサーを作成"""
    parser = argparse.ArgumentParser(
        description='AWS Cognito Identity Provider Service CLI Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  # ユーザー情報取得
  python cognito_client.py --token YOUR_TOKEN get-user

  # 属性更新
  python cognito_client.py --token YOUR_TOKEN update-attributes --given-name John --family-name Doe

  # パスワード変更
  python cognito_client.py --token YOUR_TOKEN change-password --old-password OLD --new-password NEW

  # MFA設定
  python cognito_client.py --token YOUR_TOKEN set-mfa --totp-enabled --totp-preferred

  # デバイス一覧
  python cognito_client.py --token YOUR_TOKEN list-devices
        """
    )
    
    # 共通オプション
    parser.add_argument('--token', '-t', required=True,
                       help='Cognito Access Token')
    parser.add_argument('--region', '-r', default='us-west-2',
                       help='AWS Region (default: us-west-2)')
    parser.add_argument('--json', action='store_true',
                       help='JSON形式で出力')
    
    # サブコマンド
    subparsers = parser.add_subparsers(dest='command', help='利用可能なコマンド')
    
    # ユーザー情報管理
    subparsers.add_parser('get-user', help='ユーザー情報を取得')
    
    update_attrs = subparsers.add_parser('update-attributes', help='ユーザー属性を更新')
    update_attrs.add_argument('--given-name', help='名前')
    update_attrs.add_argument('--family-name', help='姓')
    update_attrs.add_argument('--email', help='メールアドレス')
    update_attrs.add_argument('--phone-number', help='電話番号 (+81901234567形式)')
    update_attrs.add_argument('--locale', help='ロケール (ja_JP等)')
    update_attrs.add_argument('--custom-attr', nargs=2, metavar=('NAME', 'VALUE'), 
                             action='append', help='カスタム属性 (複数指定可能)')
    
    delete_attrs = subparsers.add_parser('delete-attributes', help='ユーザー属性を削除')
    delete_attrs.add_argument('attributes', nargs='+', help='削除する属性名')
    
    # 属性検証
    verify_code = subparsers.add_parser('get-verification-code', help='属性検証コードを要求')
    verify_code.add_argument('attribute', help='検証する属性名 (email, phone_number等)')
    
    verify_attr = subparsers.add_parser('verify-attribute', help='属性を検証')
    verify_attr.add_argument('attribute', help='検証する属性名')
    verify_attr.add_argument('code', help='検証コード')
    
    # パスワード管理
    change_pwd = subparsers.add_parser('change-password', help='パスワードを変更')
    change_pwd.add_argument('--old-password', required=True, help='現在のパスワード')
    change_pwd.add_argument('--new-password', required=True, help='新しいパスワード')
    
    # MFA管理
    set_mfa = subparsers.add_parser('set-mfa', help='MFA設定を変更')
    set_mfa.add_argument('--sms-enabled', action='store_true', help='SMS MFAを有効化')
    set_mfa.add_argument('--sms-preferred', action='store_true', help='SMS MFAを優先')
    set_mfa.add_argument('--totp-enabled', action='store_true', help='TOTP MFAを有効化')
    set_mfa.add_argument('--totp-preferred', action='store_true', help='TOTP MFAを優先')
    
    subparsers.add_parser('associate-totp', help='TOTP ソフトウェアトークンを関連付け')
    
    verify_totp = subparsers.add_parser('verify-totp', help='TOTP コードを検証')
    verify_totp.add_argument('code', help='6桁のTOTPコード')
    verify_totp.add_argument('--device-name', default='Python CLI', help='デバイス名')
    
    # デバイス管理
    list_dev = subparsers.add_parser('list-devices', help='デバイス一覧を取得')
    list_dev.add_argument('--limit', type=int, default=10, help='取得件数 (default: 10)')
    
    get_dev = subparsers.add_parser('get-device', help='デバイス情報を取得')
    get_dev.add_argument('device_key', help='デバイスキー')
    
    update_dev = subparsers.add_parser('update-device', help='デバイスステータスを更新')
    update_dev.add_argument('device_key', help='デバイスキー')
    update_dev.add_argument('--status', choices=['remembered', 'not_remembered'], 
                           default='remembered', help='デバイスステータス')
    
    forget_dev = subparsers.add_parser('forget-device', help='デバイスを削除')
    forget_dev.add_argument('device_key', help='デバイスキー')
    
    # セッション管理
    subparsers.add_parser('sign-out', help='全デバイスからサインアウト')
    
    revoke_tok = subparsers.add_parser('revoke-token', help='リフレッシュトークンを無効化')
    revoke_tok.add_argument('refresh_token', help='リフレッシュトークン')
    revoke_tok.add_argument('client_id', help='クライアントID')
    
    # アカウント管理
    delete_user = subparsers.add_parser('delete-user', help='自分のアカウントを削除')
    delete_user.add_argument('--confirm', action='store_true', required=True,
                            help='削除を確認 (必須)')
    
    return parser


def main():
    """メイン関数"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # クライアント初期化
    client = CognitoUserClient(region=args.region, access_token=args.token)
    result = None
    
    try:
        # コマンド実行
        if args.command == 'get-user':
            result = client.get_user()
            
        elif args.command == 'update-attributes':
            attributes = {}
            if args.given_name:
                attributes['given_name'] = args.given_name
            if args.family_name:
                attributes['family_name'] = args.family_name
            if args.email:
                attributes['email'] = args.email
            if args.phone_number:
                attributes['phone_number'] = args.phone_number
            if args.locale:
                attributes['locale'] = args.locale
            if args.custom_attr:
                for name, value in args.custom_attr:
                    attributes[name] = value
            
            if not attributes:
                print("❌ 更新する属性が指定されていません")
                return 1
            
            result = client.update_user_attributes(attributes)
            
        elif args.command == 'delete-attributes':
            result = client.delete_user_attributes(args.attributes)
            
        elif args.command == 'get-verification-code':
            result = client.get_user_attribute_verification_code(args.attribute)
            
        elif args.command == 'verify-attribute':
            result = client.verify_user_attribute(args.attribute, args.code)
            
        elif args.command == 'change-password':
            result = client.change_password(args.old_password, args.new_password)
            
        elif args.command == 'set-mfa':
            result = client.set_user_mfa_preference(
                sms_enabled=args.sms_enabled,
                sms_preferred=args.sms_preferred,
                totp_enabled=args.totp_enabled,
                totp_preferred=args.totp_preferred
            )
            
        elif args.command == 'associate-totp':
            result = client.associate_software_token()
            
        elif args.command == 'verify-totp':
            result = client.verify_software_token(args.code, args.device_name)
            
        elif args.command == 'list-devices':
            result = client.list_devices(args.limit)
            
        elif args.command == 'get-device':
            result = client.get_device(args.device_key)
            
        elif args.command == 'update-device':
            result = client.update_device_status(args.device_key, args.status)
            
        elif args.command == 'forget-device':
            result = client.forget_device(args.device_key)
            
        elif args.command == 'sign-out':
            result = client.global_sign_out()
            
        elif args.command == 'revoke-token':
            result = client.revoke_token(args.refresh_token, args.client_id)
            
        elif args.command == 'delete-user':
            print("⚠️ この操作はアカウントを完全に削除します！")
            confirm = input("本当に削除しますか？ (yes/no): ")
            if confirm.lower() == 'yes':
                result = client.delete_user()
            else:
                print("削除をキャンセルしました")
                return 0
                
        # JSON出力オプション
        if args.json and result:
            print(json.dumps(result, indent=2, ensure_ascii=False))
            
        return 0 if result and result.get('success') else 1
        
    except KeyboardInterrupt:
        print("\n操作がキャンセルされました")
        return 1
    except Exception as e:
        print(f"❌ 予期しないエラー: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
