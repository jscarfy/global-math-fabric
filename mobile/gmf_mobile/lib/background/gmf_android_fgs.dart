import 'dart:async';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'gmf_server_status.dart';
import '../capabilities/gmf_capabilities.dart';
import 'package:flutter_foreground_task/flutter_foreground_task.dart';
import 'gmf_android_permissions.dart';
import 'gmf_fgs_controller.dart';
import '../capabilities/gmf_heartbeat.dart';
import '../ffi/gmf_worker.dart';


const _storage = FlutterSecureStorage();
const _apiKeyStorageKey = 'gmf_api_key';
const _apiBaseStorageKey = 'gmf_api_base';

Future<String?> _apiKey() => _storage.read(key: _apiKeyStorageKey);
Future<String> _apiBase() async {
  final v = await _storage.read(key: _apiBaseStorageKey);
  return (v == null || v.isEmpty) ? 'http://localhost:8000' : v;
}

/// TODO: 你把這個函數接到你現有的 GMF worker：
///   - (已做) ensure device identity loaded into Rust
///   - (已做) heartbeat + signed report
///   - 你只需要在這裡呼叫「跑一輪」：lease->execute->report
Future<void> gmfRunOneIteration() async {
  // 1) probe capabilities -> adjust interval if needed
  final cap = await GmfCapabilities.probe();
  final desired = _GmfTaskHandler()._computeIntervalSec(cap); // temp helper use (cheap)
  // NOTE: real interval is maintained in handler; we will update via notification only here.

  // 2) 更新 capability heartbeat（server dispatch 需要最新）
  await GmfHeartbeat.sendOnce();

  // 3) 跑一輪：lease -> execute -> signed report
  final apiKey = await _apiKey();
  if (apiKey == null || apiKey.isEmpty) return;
  final apiBase = await _apiBase();

  final worker = GmfWorkerFFI(GmfWorkerFFI.openNative());
  final ok = worker.runOnce(apiBase, apiKey);

  // 4) 通知更新（credits/risk + last status）
  final note = ok ? 'ok interval~${desired}s' : 'fail interval~${desired}s';
  try {
    await fetchMe(apiBase, apiKey); // warm call; real update below
    FlutterForegroundTask.updateService(
      notificationTitle: 'Global Math Fabric running',
      notificationText: note,
    );
  } catch (_) {
    FlutterForegroundTask.updateService(
      notificationTitle: 'Global Math Fabric running',
      notificationText: note,
    );
  }
}

/// Foreground task entrypoint
@pragma('vm:entry-point')
void gmfForegroundStartCallback() {
  FlutterForegroundTask.setTaskHandler(_GmfTaskHandler());
}

class _GmfTaskHandler extends TaskHandler {
  bool _running = false;
  int _intervalSec = 3;
  String _lastNote = 'boot';

  int _computeIntervalSec(Map<String, dynamic> cap) {
    final battery = (cap['battery_pct'] is num) ? (cap['battery_pct'] as num).toDouble() : 100.0;
    final charging = cap['charging'] == true;
    final net = (cap['network_type'] ?? 'wifi').toString().toLowerCase();
    final thermal = (cap['thermal'] ?? 'nominal').toString().toLowerCase();

    // Conservative ladder:
    // - best: charging + wifi + nominal/fair => 3s
    // - ok: wifi + not critical => 10s
    // - low power/heat/cellular => 30s
    // - very low battery and not charging => 60s
    if (thermal == 'critical' || thermal == 'serious') return 30;
    if (!charging && battery < 15) return 60;
    if (net != 'wifi' && net != 'ethernet') return 30;
    if (charging && (net == 'wifi' || net == 'ethernet') && (thermal == 'nominal' || thermal == 'fair')) return 3;
    if (net == 'wifi' || net == 'ethernet') return 10;
    return 30;
  }

  Future<void> _updateNotification(String apiBase, String apiKey, String note) async {
    try {
      final me = await fetchMe(apiBase, apiKey);
      final credits = me?.creditsTotal ?? 0;
      final risk = me?.riskScore ?? 0.0;
      FlutterForegroundTask.updateService(
        notificationTitle: 'Global Math Fabric running',
        notificationText: 'credits=$credits  risk=${risk.toStringAsFixed(1)}  $note',
      );
    } catch (_) {
      FlutterForegroundTask.updateService(
        notificationTitle: 'Global Math Fabric running',
        notificationText: note,
      );
    }
  }

  void _armTimer() {
    _timer?.cancel();
    _timer = Timer.periodic(Duration(seconds: _intervalSec), (_) async {
      if (_running) return;
      _running = true;
      try { await gmfRunOneIteration(); } catch (_) {}
      _running = false;
    });
  }



  @override
  Future<void> onStart(DateTime timestamp, TaskStarter starter) async {
    final enabled = await GmfFgsController.isEnabled();
    if (!enabled) {
      try { await FlutterForegroundTask.stopService(); } catch (_) {}
      return;
    }
    // 立刻跑一輪，並啟動自適應循環
    try {
      final cap = await GmfCapabilities.probe();
      _intervalSec = _computeIntervalSec(cap);

      final apiKey = await _apiKey();
      final apiBase = await _apiBase();
      if (apiKey != null) {
        await _updateNotification(apiBase, apiKey, 'interval=${_intervalSec}s start');
      }
      await gmfRunOneIteration();
    } catch (_) {}

    _armTimer();
  }

  @override
  Future<void> onRepeatEvent(DateTime timestamp) async {
    if (_running) return;
    _running = true;
    try { await gmfRunOneIteration(); } catch (_) {}
    _running = false;
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
