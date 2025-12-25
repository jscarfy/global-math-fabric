import 'dart:convert';
import 'package:crypto/crypto.dart' as c;
import 'package:cryptography/cryptography.dart';

String sha256HexBytes(List<int> bytes) {
  final h = c.sha256.convert(bytes).bytes;
  return h.map((b)=>b.toRadixString(16).padLeft(2,'0')).join();
}

Future<String> signClaimPayloadB64({
  required Map<String, dynamic> claimPayload,
  required String devicePrivSeedB64,
}) async {
  final ed = Ed25519();
  final seed = base64Decode(devicePrivSeedB64);
  final keyPair = await ed.newKeyPairFromSeed(seed);
  final payloadBytes = utf8.encode(jsonEncode(_canonicalizeJson(claimPayload)));
  final msg = c.sha256.convert(payloadBytes).bytes;
  final sig = await ed.sign(msg, keyPair: keyPair);
  return base64Encode(sig.bytes);
}

// Minimal “canonicalization” for MVP: stable JSON encoding with sorted keys.
// Later你可以替換成 RFC8785(JCS) 的 Dart 實作，對齊 Rust/JCS 完全一致。
dynamic _canonicalizeJson(dynamic v) {
  if (v is Map) {
    final keys = v.keys.map((k)=>k.toString()).toList()..sort();
    final m = <String,dynamic>{};
    for (final k in keys) {
      m[k]=_canonicalizeJson(v[k]);
    }
    return m;
  } else if (v is List) {
    return v.map(_canonicalizeJson).toList();
  } else {
    return v;
  }
}

Map<String, dynamic> makeClaimPayload({
  required String taskId,
  required int cpuMs,
  required int gpuMs,
  required List<Map<String,dynamic>> artifacts,
}) {
  return {
    "task_id": taskId,
    "started_at": DateTime.now().toUtc().toIso8601String(),
    "ended_at": DateTime.now().toUtc().toIso8601String(),
    "metrics": {
      "cpu_ms": cpuMs,
      "gpu_ms": gpuMs,
      "bytes_in": 0,
      "bytes_out": 0,
    },
    "artifacts": artifacts,
  };
}
