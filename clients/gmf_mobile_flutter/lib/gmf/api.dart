import 'dart:convert';
import 'package:http/http.dart' as http;

class GmfApi {
  final String base; // e.g. http://your-server:8080
  GmfApi(this.base);

  Uri _u(String p) => Uri.parse(base.replaceAll(RegExp(r'/*$'), '') + p);

  Future<Map<String, dynamic>> policyCurrent() async {
    final r = await http.get(_u('/work/policy/current'));
    if (r.statusCode ~/ 100 != 2) throw Exception('policy/current ${r.statusCode}: ${r.body}');
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  Future<void> deviceRegister({
    required String deviceId,
    required String platform,
    required String topics,
    required String enrollToken,
    required String pubkeyHex,
  }) async {
    final body = {
      'device_id': deviceId,
      'platform': platform,
      'topics': topics,
      'enroll_token': enrollToken,
      'device_pubkey_ed25519': pubkeyHex,
    };
    final r = await http.post(_u('/work/device_register'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(body));
    if (r.statusCode ~/ 100 != 2) throw Exception('device_register ${r.statusCode}: ${r.body}');
  }

  Future<Map<String, dynamic>> lease({
    required String deviceId,
    required String topics,
  }) async {
    final body = {'device_id': deviceId, 'topics': topics};
    final r = await http.post(_u('/work/jobs/lease'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(body));
    if (r.statusCode ~/ 100 != 2) throw Exception('lease ${r.statusCode}: ${r.body}');
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> submit(Map<String, dynamic> payload) async {
    final r = await http.post(_u('/work/submit'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(payload));
    if (r.statusCode ~/ 100 != 2) throw Exception('submit ${r.statusCode}: ${r.body}');
    return jsonDecode(r.body) as Map<String, dynamic>;
  }
}
