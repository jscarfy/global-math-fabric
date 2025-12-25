import 'dart:io';
import 'foreground_android.dart';
import 'tray.dart';

enum GMFStatus {
  starting,
  running,
  paused,
  blockedNoConsent,
  blockedNoToken,
  blockedNotCharging,
  blockedNotWifi,
  stopped,
}

class RuntimeStatus {
  static GMFStatus _s = GMFStatus.stopped;
  static String _detail = "";

  static GMFStatus get status => _s;
  static String get detail => _detail;

  static Future<void> set(GMFStatus s, {String detail = ""}) async {
    _s = s;
    _detail = detail;

    final text = _render();
    // Desktop: tray tooltip
    try { await GMFTrayStatus.set(text); } catch (_) {}
    // Android: foreground notification text
    if (Platform.isAndroid) {
      final title = (s == GMFStatus.running) ? "GMF is contributing" : "GMF status";
      await GMFForegroundAndroid.update(title, text);
    }
  }

  static String _render() {
    switch (_s) {
      case GMFStatus.starting: return "Starting…";
      case GMFStatus.running: return "Running: $_detail";
      case GMFStatus.paused: return "Paused";
      case GMFStatus.blockedNoConsent: return "Blocked: consent missing";
      case GMFStatus.blockedNoToken: return "Blocked: token missing";
      case GMFStatus.blockedNotCharging: return "Blocked: not charging";
      case GMFStatus.blockedNotWifi: return "Blocked: not on Wi-Fi/Ethernet";
      case GMFStatus.stopped: return "Stopped";
    }
  }
}
