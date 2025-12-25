import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:ffi/ffi.dart';

typedef _TakeNative = ffi.Pointer<ffi.Char> Function();
typedef _FreeNative = ffi.Void Function(ffi.Pointer<ffi.Char>);

class GmfReceiptFFI {
  final ffi.DynamicLibrary dylib;
  late final ffi.Pointer<ffi.Char> Function() _take =
      dylib.lookupFunction<_TakeNative, ffi.Pointer<ffi.Char> Function()>('gmf_take_last_receipt_json');
  late final void Function(ffi.Pointer<ffi.Char>) _free =
      dylib.lookupFunction<_FreeNative, void Function(ffi.Pointer<ffi.Char>)>('gmf_free_c_string');

  GmfReceiptFFI(this.dylib);

  static ffi.DynamicLibrary openNative() {
    if (Platform.isIOS) return ffi.DynamicLibrary.process();
    if (Platform.isAndroid) return ffi.DynamicLibrary.open('libgmf_android_ffi.so');
    throw UnsupportedError('receipt ffi only for iOS/Android');
  }

  String? takeReceiptJson() {
    final ptr = _take();
    if (ptr.address == 0) return null;
    final s = ptr.cast<ffi.Utf8>().toDartString();
    _free(ptr);
    return s;
  }
}
