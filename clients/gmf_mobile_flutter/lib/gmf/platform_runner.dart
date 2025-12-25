import 'package:flutter/services.dart';

class PlatformRunner {
  static const _ch = MethodChannel("gmf.platform_runner");
  static Future<void> startBackground() async {
    await _ch.invokeMethod("startBackground");
  }
  static Future<void> stopBackground() async {
    await _ch.invokeMethod("stopBackground");
  }
}
