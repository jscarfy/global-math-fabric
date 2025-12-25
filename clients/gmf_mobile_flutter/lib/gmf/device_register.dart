import 'dart:convert';
import 'package:http/http.dart' as http;
import 'device_identity.dart';

class DeviceRegister {
  static Future<void> ensureRegistered({
    required String baseUrl,
    required String token,
  }) async {
    final did = await DeviceIdentity.getOrCreate();
    final pub = did["pubkey_hex"]!;
    // register signature binds to account_id on server side via token;
    // payload includes account_id optional (server enforces token account anyway)
    final me = await http.get(Uri.parse("$baseUrl/api/account/me"), headers: {"Authorization":"Bearer $token"});
    if (me.statusCode >= 300) {
      throw Exception("me failed: ${me.statusCode} ${me.body}");
    }
    final meJ = jsonDecode(me.body) as Map<String, dynamic>;
    final accountId = meJ["account_id"] as String;

    final sig = await DeviceIdentityRegister.signRegister(accountId: accountId, devicePubkeyHex: pub);
    final payload = {
      "account_id": accountId,
      "device_pubkey": pub,
      "device_sig": sig,
      "device_msg_version": "gmf:register:v1",
    };

    final uri = Uri.parse("$baseUrl/api/device/register");
    final r = await http.post(uri,
        headers: {"Content-Type":"application/json", "Authorization":"Bearer $token"},
        body: jsonEncode(payload));
    if (r.statusCode >= 300) {
      throw Exception("device register failed: ${r.statusCode} ${r.body}");
    }
  }
}
