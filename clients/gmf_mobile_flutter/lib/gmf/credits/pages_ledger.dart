import 'dart:convert';
import 'package:http/http.dart' as http;
import '../build_config.dart';

class PagesLedger {
  // Reads public SSR jsonl for a date: releases/ledger/ssr/YYYY-MM-DD.jsonl
  Future<int> creditsForDeviceOnDate(String yyyyMmDd, String deviceIdHex) async {
    final url = "${BuildConfig.pagesBase}/releases/ledger/ssr/$yyyyMmDd.jsonl";
    final res = await http.get(Uri.parse(url));
    if (res.statusCode != 200) return 0;

    final lines = const LineSplitter().convert(res.body);
    var sum = 0;
    for (final line in lines) {
      if (line.trim().isEmpty) continue;
      final obj = jsonDecode(line) as Map<String, dynamic>;
      final payload = obj["receipt_payload"] as Map<String, dynamic>?;
      if (payload == null) continue;
      if (payload["device_id"] == deviceIdHex) {
        final d = payload["credits_delta_micro"];
        if (d is int) sum += d;
      }
    }
    return sum;
  }
}
