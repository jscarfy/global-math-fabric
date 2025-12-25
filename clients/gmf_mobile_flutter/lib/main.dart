import 'dart:async';
import 'package:flutter/material.dart';
import 'gmf/settings_page.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:workmanager/workmanager.dart';

import 'gmf/api.dart';
import 'gmf/runner.dart';

const bgTaskName = "gmfBackgroundTick";

void callbackDispatcher() {
  Workmanager().executeTask((task, inputData) async {
    if (task != bgTaskName) return Future.value(true);

    final prefs = await SharedPreferences.getInstance();
    final consent = prefs.getBool('consent') ?? false;
    final enabled = prefs.getBool('enabled') ?? false;
    if (!consent || !enabled) return Future.value(true);

    final apiBase = prefs.getString('api') ?? '';
    final token = prefs.getString('enrollToken') ?? '';
    final topics = prefs.getString('topics') ?? 'nt';
    final platform = prefs.getString('platform') ?? 'mobile';
    final deviceId = prefs.getString('deviceId') ?? '';

    if (apiBase.isEmpty || token.isEmpty || deviceId.isEmpty) return Future.value(true);

    final runner = MobileRunner(
      api: GmfApi(apiBase),
      enrollToken: token,
      topics: topics,
      platform: platform,
      deviceId: deviceId,
    );

    try {
      await runner.runOnce();
    } catch (_) {
      // swallow in background tick
    }
    return Future.value(true);
  });
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  Workmanager().initialize(callbackDispatcher, isInDebugMode: false);
  runApp(const App());
}

class App extends StatefulWidget {
  const App({super.key});
  @override State<App> createState() => _AppState();
}

class _AppState extends State<App> {
  bool consent = false;
  bool enabled = false;

  final apiCtrl = TextEditingController(text: 'http://YOUR_SERVER:8080');
  final tokenCtrl = TextEditingController(text: 'PASTE_ENROLL_TOKEN');
  final topicsCtrl = TextEditingController(text: 'nt');

  Timer? fgTimer;
  String status = 'idle';

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      consent = prefs.getBool('consent') ?? false;
      enabled = prefs.getBool('enabled') ?? false;
      apiCtrl.text = prefs.getString('api') ?? apiCtrl.text;
      tokenCtrl.text = prefs.getString('enrollToken') ?? tokenCtrl.text;
      topicsCtrl.text = prefs.getString('topics') ?? topicsCtrl.text;
    });
  }

  Future<void> _save() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('consent', consent);
    await prefs.setBool('enabled', enabled);
    await prefs.setString('api', apiCtrl.text.trim());
    await prefs.setString('enrollToken', tokenCtrl.text.trim());
    await prefs.setString('topics', topicsCtrl.text.trim());
    // platform + deviceId
    final plat = Theme.of(context).platform == TargetPlatform.iOS ? 'ios' : 'android';
    await prefs.setString('platform', plat);
    final cur = prefs.getString('deviceId');
    if (cur == null || cur.isEmpty) {
      final did = await MobileRunner.ensureDeviceId();
      await prefs.setString('deviceId', did);
    }
  }

  Future<void> _startForegroundLoop() async {
    await _save();
    fgTimer?.cancel();
    setState(() => status = 'foreground running');
    fgTimer = Timer.periodic(const Duration(seconds: 5), (_) async {
      final prefs = await SharedPreferences.getInstance();
      if (!(prefs.getBool('consent') ?? false) || !(prefs.getBool('enabled') ?? false)) return;
      final runner = MobileRunner(
        api: GmfApi(prefs.getString('api')!),
        enrollToken: prefs.getString('enrollToken')!,
        topics: prefs.getString('topics') ?? 'nt',
        platform: prefs.getString('platform') ?? 'mobile',
        deviceId: prefs.getString('deviceId')!,
      );
      try {
        await runner.runOnce();
      } catch (_) {}
    });
  }

  Future<void> _stopForegroundLoop() async {
    fgTimer?.cancel();
    setState(() => status = 'stopped');
  }

  Future<void> _enableBackground() async {
    await _save();
    // Android: periodic background (15min minimal typical)
    await Workmanager().registerPeriodicTask(
      "gmfPeriodic",
      bgTaskName,
      frequency: const Duration(minutes: 15),
      constraints: Constraints(
        networkType: NetworkType.connected,
        requiresCharging: true,
      ),
      backoffPolicy: BackoffPolicy.linear,
      backoffPolicyDelay: const Duration(minutes: 1),
    );
    setState(() => status = 'background scheduled');
  }

  Future<void> _disableBackground() async {
    await Workmanager().cancelAll();
    setState(() => status = 'background cancelled');
  }

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'GMF Mobile',
      home: Scaffold(
        appBar: AppBar(title: const Text('Global Math Fabric (Mobile)')),
        body: Padding(
          padding: const EdgeInsets.all(16),
          child: ListView(
            children: [
              Text('Status: $status'),
              const SizedBox(height: 12),

              SwitchListTile(
                title: const Text('I consent to contribute compute (I can stop anytime)'),
                value: consent,
                onChanged: (v) => setState(() => consent = v),
              ),
              SwitchListTile(
                title: const Text('Enable contributions'),
                value: enabled,
                onChanged: (v) => setState(() => enabled = v),
              ),

              const SizedBox(height: 12),
              TextField(controller: apiCtrl, decoration: const InputDecoration(labelText: 'API base')),
              TextField(controller: tokenCtrl, decoration: const InputDecoration(labelText: 'Enroll token')),
              TextField(controller: topicsCtrl, decoration: const InputDecoration(labelText: 'Topics')),

              const SizedBox(height: 16),
              ElevatedButton(onPressed: () async { await _save(); setState(() => status = 'saved'); }, child: const Text('Save settings')),

              const Divider(height: 32),

              ElevatedButton(onPressed: () async { if (consent && enabled) await _startForegroundLoop(); }, child: const Text('Start (foreground loop)')),
              ElevatedButton(onPressed: _stopForegroundLoop, child: const Text('Stop foreground')),

              const SizedBox(height: 12),
              ElevatedButton(onPressed: () async { if (consent && enabled) await _enableBackground(); }, child: const Text('Enable background (charging+network)')),
              ElevatedButton(onPressed: _disableBackground, child: const Text('Disable background')),
            ],
          ),
        ),
      ),
    );
  }
}
