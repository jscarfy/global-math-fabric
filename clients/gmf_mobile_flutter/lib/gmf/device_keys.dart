import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class DeviceKeys {
  static const _kSk = 'gmf_ed25519_sk';
  static const _kPk = 'gmf_ed25519_pk';
  static final _storage = FlutterSecureStorage();

  static final Ed25519 _ed = Ed25519();

  static Future<SimpleKeyPair> loadOrCreate() async {
    final skB64 = await _storage.read(key: _kSk);
    final pkB64 = await _storage.read(key: _kPk);

    if (skB64 != null && pkB64 != null) {
      final sk = base64Decode(skB64);
      final pk = base64Decode(pkB64);
      return SimpleKeyPairData(sk, type: KeyPairType.ed25519, publicKey: SimplePublicKey(pk, type: KeyPairType.ed25519));
    }

    final kp = await _ed.newKeyPair();
    final kpData = await kp.extract();
    await _storage.write(key: _kSk, value: base64Encode(kpData.bytes));
    await _storage.write(key: _kPk, value: base64Encode(kpData.publicKey.bytes));
    return kp;
  }

  static Future<String> pubkeyHex(SimpleKeyPair kp) async {
    final pub = (await kp.extractPublicKey()).bytes;
    final sb = StringBuffer();
    for (final b in pub) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  static Future<String> signB64(SimpleKeyPair kp, List<int> msg) async {
    final sig = await _ed.sign(msg, keyPair: kp);
    return base64Encode(sig.bytes);
  }
}
