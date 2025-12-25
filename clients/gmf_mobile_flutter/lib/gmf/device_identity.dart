import 'dart:convert';
import 'dart:io';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class DeviceIdentity {
  static const _storage = FlutterSecureStorage();
  static const _kPub = "gmf_device_pubkey_hex_v1";
  static const _kPriv = "gmf_device_privkey_hex_v1";

  static final _algo = Ed25519();

  static Future<Map<String, String>> getOrCreate() async {
    // Prefer secure storage
    String? pub = await _storage.read(key: _kPub);
    String? priv = await _storage.read(key: _kPriv);

    if (pub != null && priv != null && pub.length == 64 && priv.length == 64) {
      return {"pubkey_hex": pub, "privkey_hex": priv};
    }

    // Generate
    final kp = await _algo.newKeyPair();
    final pubBytes = (await kp.extractPublicKey()).bytes;
    final privBytes = await kp.extractPrivateKeyBytes();

    pub = _toHex(pubBytes);
    priv = _toHex(privBytes);

    try {
      await _storage.write(key: _kPub, value: pub);
      await _storage.write(key: _kPriv, value: priv);
      return {"pubkey_hex": pub, "privkey_hex": priv};
    } catch (_) {
      // Fallback to file (desktop or if secure storage not available)
      final m = {"pubkey_hex": pub, "privkey_hex": priv};
      await _writeFallbackFile(m);
      return m;
    }
  }

  static Future<String> signSubmit({
    required String jobId,
    required String leaseId,
    required String outputSha256Hex,
  }) async {
    final id = await getOrCreate();
    final priv = _fromHex(id["privkey_hex"]!);
    final keyPair = SimpleKeyPairData(priv, type: KeyPairType.ed25519);
    final msg = "gmf:v1:$jobId:$leaseId:$outputSha256Hex";
    final sig = await _algo.sign(utf8.encode(msg), keyPair: keyPair);
    return _toHex(sig.bytes);
  }

  static String submitMsg({
    required String jobId,
    required String leaseId,
    required String outputSha256Hex,
  }) => "gmf:v1:$jobId:$leaseId:$outputSha256Hex";

  static String _toHex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  static List<int> _fromHex(String h) {
    final s = h.trim();
    if (s.length % 2 != 0) throw FormatException("hex length must be even");
    final out = <int>[];
    for (var i = 0; i < s.length; i += 2) {
      out.add(int.parse(s.substring(i, i + 2), radix: 16));
    }
    return out;
  }

  static Future<void> _writeFallbackFile(Map<String, String> m) async {
    try {
      final dir = await _fallbackDir();
      final f = File("${dir.path}/gmf_device_identity_v1.json");
      await f.writeAsString(jsonEncode(m));
    } catch (_) {}
  }

  static Future<Directory> _fallbackDir() async {
    // best-effort, avoids extra dependencies
    final home = Platform.environment["HOME"] ?? Platform.environment["USERPROFILE"] ?? ".";
    final d = Directory("$home/.gmf");
    if (!await d.exists()) await d.create(recursive: true);
    return d;
  }
}

extension DeviceIdentityRegister on DeviceIdentity {
  static Future<String> signRegister({required String accountId, required String devicePubkeyHex}) async {
    final id = await getOrCreate();
    final priv = _fromHex(id["privkey_hex"]!);
    final keyPair = SimpleKeyPairData(priv, type: KeyPairType.ed25519);
    final msg = "gmf:register:v1:$accountId:${devicePubkeyHex.toLowerCase()}";
    final sig = await _algo.sign(utf8.encode(msg), keyPair: keyPair);
    return _toHex(sig.bytes);
  }
}
