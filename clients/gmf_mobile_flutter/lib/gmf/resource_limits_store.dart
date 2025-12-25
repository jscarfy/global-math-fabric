import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class ResourceLimits {
  final bool chargingOnly;
  final bool unmeteredOnly;
  final int cpuCapPercent; // soft cap; desktop enforced via worker throttling

  ResourceLimits({
    required this.chargingOnly,
    required this.unmeteredOnly,
    required this.cpuCapPercent,
  });

  static ResourceLimits defaults() => ResourceLimits(
        chargingOnly: true,
        unmeteredOnly: true,
        cpuCapPercent: 25,
      );

  Map<String, String> toMap() => {
        "chargingOnly": chargingOnly ? "1" : "0",
        "unmeteredOnly": unmeteredOnly ? "1" : "0",
        "cpuCapPercent": cpuCapPercent.toString(),
      };

  static ResourceLimits fromMap(Map<String, String?> m) {
    final d = defaults();
    return ResourceLimits(
      chargingOnly: (m["chargingOnly"] ?? (d.chargingOnly ? "1" : "0")) == "1",
      unmeteredOnly: (m["unmeteredOnly"] ?? (d.unmeteredOnly ? "1" : "0")) == "1",
      cpuCapPercent: int.tryParse(m["cpuCapPercent"] ?? "") ?? d.cpuCapPercent,
    );
  }
}

class ResourceLimitsStore {
  static const _s = FlutterSecureStorage();
  static const _p = "gmf_limits_v1_";

  static Future<ResourceLimits> get() async {
    final m = <String, String?>{};
    for (final k in ["chargingOnly", "unmeteredOnly", "cpuCapPercent"]) {
      m[k] = await _s.read(key: _p + k);
    }
    return ResourceLimits.fromMap(m);
  }

  static Future<void> set(ResourceLimits v) async {
    final m = v.toMap();
    for (final e in m.entries) {
      await _s.write(key: _p + e.key, value: e.value);
    }
  }
}
