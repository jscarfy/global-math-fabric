import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';

class ConsentStore {
  static const _kKey = "gmf_consent_v1";
  static Future<bool> hasConsent() async {
    final sp = await SharedPreferences.getInstance();
    final s = sp.getString(_kKey);
    if (s == null) return false;
    try {
      final j = jsonDecode(s) as Map<String, dynamic>;
      return j["ok"] == true;
    } catch (_) {
      return false;
    }
  }

  static Future<void> setConsent(bool ok) async {
    final sp = await SharedPreferences.getInstance();
    final payload = jsonEncode({
      "ok": ok,
      "ts": DateTime.now().toUtc().toIso8601String(),
    });
    await sp.setString(_kKey, payload);
  }
}
