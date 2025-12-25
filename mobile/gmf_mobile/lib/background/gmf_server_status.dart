import 'dart:convert';
import 'package:http/http.dart' as http;

class GmfMe {
  final String clientId;
  final String displayName;
  final int creditsTotal;
  final double riskScore;

  GmfMe({required this.clientId, required this.displayName, required this.creditsTotal, required this.riskScore});

  static GmfMe fromJson(Map<String, dynamic> j) => GmfMe(
    clientId: j['client_id'] as String? ?? '',
    displayName: j['display_name'] as String? ?? '',
    creditsTotal: (j['credits_total'] as num?)?.toInt() ?? 0,
    riskScore: (j['risk_score'] as num?)?.toDouble() ?? 0.0,
  );
}

Future<GmfMe?> fetchMe(String apiBase, String apiKey) async {
  final base = apiBase.replaceAll(RegExp(r'/+$'), '');
  final uri = Uri.parse('$base/credits/me');
  final r = await http.get(uri, headers: {"X-API-Key": apiKey});
  if (r.statusCode < 200 || r.statusCode >= 300) return null;
  final j = jsonDecode(r.body) as Map<String, dynamic>;
  return GmfMe.fromJson(j);
}
