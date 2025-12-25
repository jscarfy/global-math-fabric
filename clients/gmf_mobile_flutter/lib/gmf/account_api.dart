import 'dart:convert';
import 'package:http/http.dart' as http;

class AccountApi {
  static Future<Map<String, dynamic>> create({required String baseUrl, required String displayName}) async {
    final uri = Uri.parse("$baseUrl/api/account/create");
    final r = await http.post(uri,
        headers: {"Content-Type":"application/json"},
        body: jsonEncode({"display_name": displayName}));
    if (r.statusCode >= 300) throw Exception("create account failed: ${r.statusCode} ${r.body}");
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  static Future<Map<String, dynamic>> me({required String baseUrl, required String token}) async {
    final uri = Uri.parse("$baseUrl/api/account/me");
    final r = await http.get(uri, headers: {"Authorization":"Bearer $token"});
    if (r.statusCode >= 300) throw Exception("me failed: ${r.statusCode} ${r.body}");
    return jsonDecode(r.body) as Map<String, dynamic>;
  }
}
