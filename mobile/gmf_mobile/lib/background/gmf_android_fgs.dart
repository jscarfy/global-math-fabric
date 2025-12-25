import 'dart:async';
import 'dart:io';

import 'package:flutter_foreground_task/flutter_foreground_task.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../capabilities/gmf_capabilities.dart';
import '../capabilities/gmf_heartbeat.dart';
import '../ffi/gmf_worker.dart';
import 'gmf_android_permissions.dart';
import 'gmf_interval_policy.dart';
import 'gmf_server_status.dart';
import 'gmf_fgs_controller.dart';

const _storage = FlutterSecureStorage();
const _apiKeyStorageKey = 'gmf_api_key';
const _apiBaseStorageKey = 'gmf_api_base';

Future<String?> _apiKey() => _storage.read(key: _apiKeyStorageKey);
Future<String> _apiBase() async {
  final v = await _storage.read(key: _apiBaseStorageKey);
  return (v == null || v.isEmpty) ? 'http://localhost:8000' : v;
}

/// One iteration: probe cap -> heartbeat -> runOnce (lease->execute->signed report)
Future<bool> gmfRunOneIteration() async {
  // Keep server dispatch aware (battery/network/thermal)
  await GmfHeartbeat.sendOnce();

  final apiKey = await _apiKey();
  if (apiKey == null || apiKey.isEmpty) return false;
  final apiBase = await _apiBase();

  final worker = GmfWorkerFFI(GmfWorkerFFI.openNative());
  final ok = worker.runOnce(apiBase, apiKey);
  return ok;
}

@pragma('vm:entry-point')
void gmfForegroundStartCallback() {
  FlutterForegroundTask.setTaskHandler(_GmfTaskHandler());
}

class _GmfTaskHandler extends TaskHandler {
  bool _running = false;
  int _intervalSec = 3;
  Timer? _timer;

  // notification /me polling throttle
  DateTime _lastMeFetch = DateTime.fromMillisecondsSinceEpoch(0);
  int _cachedCredits = 0;
  double _cachedRisk = 0.0;

  void _armTimer() {
    _timer?.cancel();
    _timer = Timer.periodic(Duration(seconds: _intervalSec), (_) async {
      if (_running) return;
      _running = true;
      try {
        await _tick();
      } finally {
        _running = false;
      }
    });
  }

  Future<void> _maybeUpdateMe(String apiBase, String apiKey) async {
    final now = DateTime.now();
    if (now.difference(_lastMeFetch).inSeconds < 30) return;
    _lastMeFetch = now;
    final me = await fetchMe(apiBase, apiKey);
    if (me != null) {
      _cachedCredits = me.creditsTotal;
      _cachedRisk = me.riskScore;
    }
  }

  Future<void> _notify(String text) async {
    FlutterForegroundTask.updateService(
      notificationTitle: 'Global Math Fabric running',
      notificationText: text,
    );
  }

  Future<void> _tick() async {
    // Gate on persisted toggle (enables autoRunOnBoot safely)
    final enabled = await GmfFgsController.isEnabled();
    if (!enabled) {
      try { await FlutterForegroundTask.stopService(); } catch (_) {}
      return;
    }

    // Probe capabilities and adapt interval
    final cap = await GmfCapabilities.probe();
    final desired = GmfIntervalPolicy.computeIntervalSec(cap);
    if (desired != _intervalSec) {
      _intervalSec = desired;
      _armTimer();
    }

    // Run one iteration
    bool ok = false;
    try {
      ok = await gmfRunOneIteration();
    } catch (_) {
      ok = false;
    }

    // Update notification with credits/risk (throttled)
    final apiKey = await _apiKey();
    final apiBase = await _apiBase();
    if (apiKey != null && apiKey.isNotEmpty) {
      try { await _maybeUpdateMe(apiBase, apiKey); } catch (_) {}
    }

    final net = (cap['network_type'] ?? 'wifi').toString();
    final batt = (cap['battery_pct'] ?? 0).toString();
    final chg = (cap['charging'] == true) ? 'chg' : 'bat';
    final therm = (cap['thermal'] ?? 'nominal').toString();

    final status = ok ? 'ok' : 'fail';
    await _notify('credits=$_cachedCredits risk=${_cachedRisk.toStringAsFixed(1)}  ${status}  int=${_intervalSec}s  $chg=$batt%  net=$net  th=$therm');
  }

  @override
  Future<void> onStart(DateTime timestamp, TaskStarter starter) async {
    // Android only
    if (!Platform.isAndroid) return;

    // If toggle is off, stop immediately (boot auto-run safe)
    final enabled = await GmfFgsController.isEnabled();
    if (!enabled) {
      try { await FlutterForegroundTask.stopService(); } catch (_) {}
      return;
    }

    await _notify('starting...');
    // First tick immediately then arm periodic
    if (!_running) {
      _running = true;
      try { await _tick(); } finally { _running = false; }
    }
    _armTimer();
  }

  @override
  Future<void> onRepeatEvent(DateTime timestamp) async {
    // plugin repeat event; we already have timer, so ignore
  }

  @override
  Future<void> onDestroy(DateTime timestamp) async {
    _timer?.cancel();
    _timer = null;
  }

  @override
  void onNotificationPressed() {
    FlutterForegroundTask.launchApp("/");
  }

  @override
  void onNotificationButtonPressed(String id) {}
}

/// Public API
Future<void> gmfStartForegroundService() async {
  if (!Platform.isAndroid) return;

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
    ),
    foregroundTaskOptions: const ForegroundTaskOptions(
      interval: 3000, // plugin repeat; our timer controls real work frequency
      isOnceEvent: false,
      autoRunOnBoot: true,
      allowWakeLock: true,
      allowWifiLock: true,
    ),
  );

  await FlutterForegroundTask.startService(
    notificationTitle: 'Global Math Fabric running',
    notificationText: 'initializing...',
    callback: gmfForegroundStartCallback,
  );
}

Future<void> gmfStopForegroundService() async {
  if (!Platform.isAndroid) return;
  await FlutterForegroundTask.stopService();
}
