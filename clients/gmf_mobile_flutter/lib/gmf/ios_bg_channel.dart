import 'package:flutter/services.dart';

/// iOS BGTaskScheduler callback entry (headless engine).
/// 先做 stub：確保整套可 build；你之後再把它接到「跑一段時間 lease/job」。
class IosBgChannel {
  static const _ch = MethodChannel("gmf.ios_bg");

  static void ensureInstalled() {
    _ch.setMethodCallHandler((call) async {
      if (call.method == "bgTick") {
        // TODO: 接你的 runner：跑 30~60 秒的一批工作，再 return
        // 必須：遵守 consent gate（你已做）
        // NOTE: iOS BGProcessingTask 不是 24/7，只是系統允許時多跑。
        return true;
      }
      return null;
    });
  }
}
