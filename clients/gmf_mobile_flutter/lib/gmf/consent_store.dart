import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class ConsentStore {
  static const _s = FlutterSecureStorage();
  static const _k = "gmf_consent_background_v1";

  static Future<bool> hasConsent() async => (await _s.read(key: _k)) == "yes";

  static Future<void> grant() async => _s.write(key: _k, value: "yes");

  static Future<void> revoke() async => _s.delete(key: _k);
}
