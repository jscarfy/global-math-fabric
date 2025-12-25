import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:crypto/crypto.dart' as c;
import 'package:jcs_dart/jcs_dart.dart';
import 'package:cryptography/cryptography.dart';

class ConsentStore {
  static const _kOptIn = 'gmf_opt_in';
  static const _storage = FlutterSecureStorage();

  Future<bool> isOptedIn() async {
    final v = await _storage.read(key: _kOptIn);
    return v == 'true';
  }

  Future<void> setOptIn(bool v) async {
    await _storage.write(key: _kOptIn, value: v ? 'true' : 'false');
  }
}

List<int> _sha256(List<int> bytes) => c.sha256.convert(bytes).bytes;

/// RFC8785(JCS) canonical bytes using jcs_dart
List<int> jcsBytesFromObject(Object obj) {
  final jsonStr = jsonEncode(obj);
  final canon = JsonCanonicalizer().canonicalize(jsonStr);
  return utf8.encode(canon);
}

Future<String> signConsentTokenB64({
  required String deviceIdHex,
  required String devicePrivSeedB64,
  required Map<String, dynamic> caps,
}) async {
  final ed = Ed25519();
  final seed = base64Decode(devicePrivSeedB64);
  final keyPair = await ed.newKeyPairFromSeed(seed);

  final payload = <String, dynamic>{
    "protocol": "gmf/consent/v1",
    "device_id": deviceIdHex,
    "granted_at": DateTime.now().toUtc().toIso8601String(),
    "scope": ["compute", "network"],
    "caps": caps,
  };

  final canonBytes = jcsBytesFromObject(payload);
  final msg = _sha256(canonBytes);
  final sig = await ed.sign(msg, keyPair: keyPair);

  final token = <String, dynamic>{
    "protocol": "gmf/consent/v1",
    "consent_payload": payload,
    "device_sig_b64": base64Encode(sig.bytes),
  };
  return jsonEncode(token);
}
