import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

typedef _RunOnceNative = ffi.Uint8 Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Char>);
typedef _RunOnceDart = int Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Char>);

class GmfWorkerFFI {
  final ffi.DynamicLibrary dylib;
  late final _RunOnceDart _runOnce =
      dylib.lookupFunction<_RunOnceNative, _RunOnceDart>('gmf_run_once');

  GmfWorkerFFI(this.dylib);

  static ffi.DynamicLibrary openNative() {
    if (Platform.isIOS) return ffi.DynamicLibrary.process();
    if (Platform.isAndroid) return ffi.DynamicLibrary.open('libgmf_android_ffi.so');
    throw UnsupportedError('gmf_run_once only implemented for iOS/Android');
  }

  bool runOnce(String apiBase, String apiKey) {
    final api = apiBase.toNativeUtf8().cast<ffi.Char>();
    final key = apiKey.toNativeUtf8().cast<ffi.Char>();
    try {
      final ok = _runOnce(api, key) != 0;
      return ok;
    } finally {
      malloc.free(api);
      malloc.free(key);
    }
  }
}

class GmfWorkerConfig {
  static const _storage = FlutterSecureStorage();
  static const _apiKeyStorageKey = 'gmf_api_key';
  static const _apiBaseStorageKey = 'gmf_api_base';

  static Future<String?> apiKey() => _storage.read(key: _apiKeyStorageKey);

  static Future<String> apiBase() async {
    final v = await _storage.read(key: _apiBaseStorageKey);
    return (v == null || v.isEmpty) ? 'http://localhost:8000' : v;
  }
}
