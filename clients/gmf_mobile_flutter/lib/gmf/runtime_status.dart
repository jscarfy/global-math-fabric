import 'dart:io';
import 'package:flutter/foundation.dart';

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

class RuntimeStatusSnapshot {
  final GMFStatus status;
  final String detail;
  const RuntimeStatusSnapshot(this.status, this.detail);
}

class RuntimeStatus {
  static RuntimeStatusSnapshot _snap = const RuntimeStatusSnapshot(GMFStatus.stopped, "");
  static final ValueNotifier<RuntimeStatusSnapshot> notifier = ValueNotifier(_snap);

  static RuntimeStatusSnapshot get snap => _snap;

  static Future<void> set(GMFStatus s, {String detail = ""}) async {
    _snap = RuntimeStatusSnapshot(s, detail);
    notifier.value = _snap;

    final text = _render(_snap);
    // Desktop tooltip
    try { await GMFTrayStatus.set(text); } catch (_) {}
    // Android foreground notification
    if (Platform.isAndroid) {
      final title = (s == GMFStatus.running) ? "GMF is contributing" : "GMF status";
      await GMFForegroundAndroid.update(title, text);
    }
  }

  static String _render(RuntimeStatusSnapshot x) {
    switch (x.status) {
      case GMFStatus.starting: return "Starting…";
      case GMFStatus.running: return x.detail.isEmpty ? "Running" : "Running: ${x.detail}";
      case GMFStatus.paused: return "Paused";
      case GMFStatus.blockedNoConsent: return "Blocked: consent missing";
      case GMFStatus.blockedNoToken: return "Blocked: token missing";
      case GMFStatus.blockedNotCharging: return "Blocked: not charging";
      case GMFStatus.blockedNotWifi: return "Blocked: not on Wi-Fi/Ethernet";
      case GMFStatus.stopped: return x.detail.isEmpty ? "Stopped" : "Stopped: ${x.detail}";
    }
  }
}
