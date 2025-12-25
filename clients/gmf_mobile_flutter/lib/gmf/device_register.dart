import 'dart:convert';
import 'package:http/http.dart' as http;
import 'device_identity.dart';

class DeviceRegister {
  static Future<void> ensureRegistered({
    required String baseUrl,
    required String accountId,
  }) async {
    final did = await DeviceIdentity.getOrCreate();
    final pub = did["pubkey_hex"]!;
    final sig = await DeviceIdentityRegister.signRegister(accountId: accountId, devicePubkeyHex: pub);

    final payload = {
      "account_id": accountId,
      "device_pubkey": pub,
      "device_sig": sig,
      "device_msg_version": "gmf:register:v1",
    };

    final uri = Uri.parse("$baseUrl/api/device/register");
    final r = await http.post(uri, headers: {"Content-Type":"application/json"}, body: jsonEncode(payload));
    if (r.statusCode >= 300) {
      throw Exception("device register failed: ${r.statusCode} ${r.body}");
    }
  }
}
