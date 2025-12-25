import 'dart:convert';
import 'package:http/http.dart' as http;

class RelayClient {
  final String baseUrl; // e.g. http://yourhost:8787
  RelayClient(this.baseUrl);

  Future<Map<String, dynamic>> postClaim({
    required Map<String, dynamic> claimPayload,
    required String devicePubB64,
    required String deviceSigB64,
  }) async {
    final body = {
      "protocol": "gmf/receipt/v1",
      "claim_payload": claimPayload,
      "device_pubkey_b64": devicePubB64,
      "device_sig_b64": deviceSigB64,
    };
    final res = await http.post(
      Uri.parse("$baseUrl/v1/claims"),
      headers: {"content-type":"application/json"},
      body: jsonEncode(body),
    );
    if (res.statusCode != 200) {
      throw Exception("relay error ${res.statusCode}: ${res.body}");
    }
    return jsonDecode(res.body) as Map<String, dynamic>;
  }
}
