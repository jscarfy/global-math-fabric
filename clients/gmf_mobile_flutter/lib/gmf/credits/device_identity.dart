import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:crypto/crypto.dart' as c;

class DeviceIdentity {
  final String devicePubKeyB64;
  final String devicePrivKeyB64; // 32-byte seed for Ed25519
  final String deviceIdHex;

  DeviceIdentity(this.devicePubKeyB64, this.devicePrivKeyB64, this.deviceIdHex);
}

class DeviceIdentityStore {
  static const _kPub = 'gmf_device_pub_b64';
  static const _kSk  = 'gmf_device_sk_b64';
  final FlutterSecureStorage _storage = const FlutterSecureStorage();
  final Ed25519 _ed = Ed25519();

  Future<DeviceIdentity> loadOrCreate() async {
    var pub = await _storage.read(key: _kPub);
    var sk  = await _storage.read(key: _kSk);
    if (pub != null && sk != null) {
      final id = _deviceIdFromPubB64(pub);
      return DeviceIdentity(pub, sk, id);
    }

    final keyPair = await _ed.newKeyPair();
    final pubBytes = await keyPair.extractPublicKey().then((k) => k.bytes);
    final seed = await keyPair.extract().then((k) => k.bytes); // seed for Ed25519 in cryptography

    pub = base64Encode(pubBytes);
    sk  = base64Encode(seed);
    await _storage.write(key: _kPub, value: pub);
    await _storage.write(key: _kSk, value: sk);

    final id = _deviceIdFromPubB64(pub);
    return DeviceIdentity(pub, sk, id);
  }

  String _deviceIdFromPubB64(String pubB64) {
    final pubBytes = base64Decode(pubB64);
    final h = c.sha256.convert(pubBytes).bytes;
    return h.map((b)=>b.toRadixString(16).padLeft(2,'0')).join();
  }
}
