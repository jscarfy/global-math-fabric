import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'gmf_capabilities.dart';

class GmfHeartbeat {
  static const _storage = FlutterSecureStorage();

  // You can change these keys to match your app’s existing storage.
  static const _apiKeyStorageKey = 'gmf_api_key';
  static const _apiBaseStorageKey = 'gmf_api_base';
  static const _identityStorageKey = 'gmf_device_identity_json_v1';

  static Future<String> _apiBase() async {
    final v = await _storage.read(key: _apiBaseStorageKey);
    return (v == null || v.isEmpty) ? "http://localhost:8000" : v;
  }

  static Future<String?> _apiKey() => _storage.read(key: _apiKeyStorageKey);

  static Future<String?> _deviceId() async {
    final j = await _storage.read(key: _identityStorageKey);
    if (j == null) return null;
    final m = jsonDecode(j) as Map<String, dynamic>;
    final deviceId = m["device_id"];
    return (deviceId is String && deviceId.isNotEmpty) ? deviceId : null;
  }

  static Future<void> sendOnce() async {
    final apiKey = await _apiKey();
    final deviceId = await _deviceId();
    if (apiKey == null || deviceId == null) {
      // Lease is now auth-required, so you should set these during onboarding.
      return;
    }

    final apiBase = await _apiBase();
    final caps = await GmfCapabilities.probe();

    final uri = Uri.parse("${apiBase.replaceAll(RegExp(r'/+$'), '')}/devices/heartbeat");
    final body = jsonEncode({"device_id": deviceId, "payload": caps});

    final r = await http.post(
      uri,
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": apiKey,
      },
      body: body,
    );

    if (r.statusCode < 200 || r.statusCode >= 300) {
      throw Exception("heartbeat failed ${r.statusCode}: ${r.body}");
    }
  }
}
