import 'dart:convert';
import 'package:crypto/crypto.dart' as c;
import 'package:cryptography/cryptography.dart';
import 'package:jcs_dart/jcs_dart.dart';

List<int> _sha256(List<int> bytes) => c.sha256.convert(bytes).bytes;

List<int> jcsBytes(Map<String, dynamic> obj) {
  final canon = JsonCanonicalizer().canonicalize(jsonEncode(obj));
  return utf8.encode(canon);
}

Future<String> signClaimPayloadB64({
  required Map<String, dynamic> claimPayload,
  required String devicePrivSeedB64,
}) async {
  final ed = Ed25519();
  final seed = base64Decode(devicePrivSeedB64);
  final keyPair = await ed.newKeyPairFromSeed(seed);

  final msg = _sha256(jcsBytes(claimPayload));
  final sig = await ed.sign(msg, keyPair: keyPair);
  return base64Encode(sig.bytes);
}

Map<String, dynamic> makeClaimPayload({
  required String taskId,
  required int cpuMs,
  required int gpuMs,
  required List<Map<String,dynamic>> artifacts,
}) {
  final now = DateTime.now().toUtc().toIso8601String();
  return {
    "task_id": taskId,
    "started_at": now,
    "ended_at": now,
    "metrics": {
      "cpu_ms": cpuMs,
      "gpu_ms": gpuMs,
      "bytes_in": 0,
      "bytes_out": 0,
    },
    "artifacts": artifacts,
  };
}
