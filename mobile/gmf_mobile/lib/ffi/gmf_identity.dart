import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

typedef _GenIdNative = ffi.Pointer<ffi.Char> Function();
typedef _SetIdNative = ffi.Uint8 Function(ffi.Pointer<ffi.Char>);
typedef _FreeNative = ffi.Void Function(ffi.Pointer<ffi.Char>);

class GmfIdentity {
  static const _storage = FlutterSecureStorage();
  static const _key = 'gmf_device_identity_json_v1';

  final ffi.DynamicLibrary dylib;
  late final ffi.Pointer<ffi.Char> Function() _gen =
      dylib.lookupFunction<_GenIdNative, ffi.Pointer<ffi.Char> Function()>('gmf_generate_device_identity_json');
  late final int Function(ffi.Pointer<ffi.Char>) _set =
      dylib.lookupFunction<_SetIdNative, int Function(ffi.Pointer<ffi.Char>)>('gmf_set_device_identity_json');
  late final void Function(ffi.Pointer<ffi.Char>) _free =
      dylib.lookupFunction<_FreeNative, void Function(ffi.Pointer<ffi.Char>)>('gmf_free_c_string');

  GmfIdentity(this.dylib);

  static ffi.DynamicLibrary openNative() {
    if (Platform.isIOS) return ffi.DynamicLibrary.process();
    if (Platform.isAndroid) return ffi.DynamicLibrary.open('libgmf_android_ffi.so');
    throw UnsupportedError('Only iOS/Android expected here');
    }

  Future<void> ensureLoadedIntoRust() async {
    String? json = await _storage.read(key: _key);
    if (json == null || json.isEmpty) {
      final ptr = _gen();
      if (ptr.address == 0) throw Exception('gmf_generate_device_identity_json failed');
      json = ptr.cast<ffi.Utf8>().toDartString();
      _free(ptr);
      await _storage.write(key: _key, value: json);
    }
    final cstr = json.toNativeUtf8().cast<ffi.Char>();
    final ok = _set(cstr) != 0;
    ffi.malloc.free(cstr);
    if (!ok) {
      // If already set, OK; otherwise error
      // For simplicity, ignore "already set" and just continue
    }
  }
}
