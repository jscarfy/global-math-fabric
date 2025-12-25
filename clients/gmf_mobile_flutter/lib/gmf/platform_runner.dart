import 'foreground_android.dart';
import 'runtime_status.dart';
import 'package:flutter/services.dart';

class PlatformRunner {
  static const _ch = MethodChannel("gmf.platform_runner");
  static Future<void> startBackground() async {
    await GMFForegroundAndroid.start();
    await RuntimeStatus.set(GMFStatus.starting);
    await _ch.invokeMethod("startBackground");
  }
  static Future<void> stopBackground() async {
    await GMFForegroundAndroid.stop();
    await RuntimeStatus.set(GMFStatus.paused);
    await _ch.invokeMethod("stopBackground");
  }
}
