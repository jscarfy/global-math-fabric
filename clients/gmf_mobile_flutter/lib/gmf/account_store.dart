import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class AccountStore {
  static const _s = FlutterSecureStorage();
  static const _kBaseUrl = "gmf_base_url_v1";
  static const _kToken = "gmf_api_token_v1";
  static const _kAccountId = "gmf_account_id_v1";

  static Future<void> setBaseUrl(String v) => _s.write(key: _kBaseUrl, value: v);
  static Future<String> getBaseUrl() async => (await _s.read(key: _kBaseUrl)) ?? "http://10.0.2.2:8080";

  static Future<void> setToken(String v) => _s.write(key: _kToken, value: v);
  static Future<String?> getToken() => _s.read(key: _kToken);

  static Future<void> setAccountId(String v) => _s.write(key: _kAccountId, value: v);
  static Future<String?> getAccountId() => _s.read(key: _kAccountId);

  static Future<void> clear() async {
    await _s.delete(key: _kToken);
    await _s.delete(key: _kAccountId);
  }
}
