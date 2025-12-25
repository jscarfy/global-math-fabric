import 'dart:async';
import 'package:flutter_foreground_task/flutter_foreground_task.dart';
import 'gmf_android_permissions.dart';
import '../capabilities/gmf_heartbeat.dart';

/// TODO: 你把這個函數接到你現有的 GMF worker：
///   - (已做) ensure device identity loaded into Rust
///   - (已做) heartbeat + signed report
///   - 你只需要在這裡呼叫「跑一輪」：lease->execute->report
Future<void> gmfRunOneIteration() async {
  // 保持 dispatch cap aware（heartbeat 最新）
  await GmfHeartbeat.sendOnce();

  // TODO: 呼叫你現有的 Rust/FFI worker 單輪：
  // e.g. await GmfRust.runOnce();  (你 repo 內實際的入口名稱自行替換)
}

/// Foreground task entrypoint
@pragma('vm:entry-point')
void gmfForegroundStartCallback() {
  FlutterForegroundTask.setTaskHandler(_GmfTaskHandler());
}

class _GmfTaskHandler extends TaskHandler {
  Timer? _timer;

  @override
  Future<void> onStart(DateTime timestamp, TaskStarter starter) async {
    // 立刻跑一輪，然後啟動循環
    try { await gmfRunOneIteration(); } catch (_) {}
    _timer = Timer.periodic(const Duration(seconds: 3), (_) async {
      try { await gmfRunOneIteration(); } catch (_) {}
    });
  }

  @override
  Future<void> onRepeatEvent(DateTime timestamp) async {
    // plugin 的 repeat 也可能觸發；保守再跑一次
    try { await gmfRunOneIteration(); } catch (_) {}
  }

  @override
  Future<void> onDestroy(DateTime timestamp) async {
    _timer?.cancel();
    _timer = null;
  }

  @override
  void onNotificationButtonPressed(String id) {}

  @override
  void onNotificationPressed() {
    FlutterForegroundTask.launchApp("/");
  }
}

/// 供 UI 呼叫：啟動前台服務（Android 可做到近似 24/7，iOS 不行）
Future<void> gmfStartForegroundService() async {
  await gmfRequestAndroidNotificationPermission();

  FlutterForegroundTask.init(
    androidNotificationOptions: AndroidNotificationOptions(
      channelId: 'gmf_fgs',
      channelName: 'Global Math Fabric',
      channelDescription: 'Contributing compute to Global Math Fabric',
      channelImportance: NotificationChannelImportance.LOW,
      priority: NotificationPriority.LOW,
      iconData: const NotificationIconData(
        resType: ResourceType.mipmap,
        resPrefix: ResourcePrefix.ic,
        name: 'launcher',
      ),
      buttons: const [],
    ),
    foregroundTaskOptions: const ForegroundTaskOptions(
      interval: 3000,
      isOnceEvent: false,
      autoRunOnBoot: true,
      allowWakeLock: true,
      allowWifiLock: true,
    ),
  );

  await FlutterForegroundTask.startService(
    notificationTitle: 'Global Math Fabric running',
    notificationText: 'Contributing compute (tap to open)',
    callback: gmfForegroundStartCallback,
  );
}

Future<void> gmfStopForegroundService() async {
  await FlutterForegroundTask.stopService();
}
