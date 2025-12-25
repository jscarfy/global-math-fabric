import 'dart:io';
import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';
import 'consent.dart';
import 'platform_runner.dart';

class GmfSettingsPage extends StatefulWidget {
  const GmfSettingsPage({super.key});
  @override
  State<GmfSettingsPage> createState() => _GmfSettingsPageState();
}

class _GmfSettingsPageState extends State<GmfSettingsPage> {
  bool _consented = false;
  bool _bgOn = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final ok = await ConsentStore.hasConsent();
    setState(() {
      _consented = ok;
      // bg state is mirrored by native; keep UI simple: bgOn tracks consent for now
      _bgOn = false;
    });
  }

  Future<void> _requestAndroidNotificationPermissionIfNeeded() async {
    if (!Platform.isAndroid) return;
    final st = await Permission.notification.status;
    if (!st.isGranted) {
      await Permission.notification.request();
    }
  }

  Future<void> _toggleConsent(bool v) async {
    await ConsentStore.setConsent(v);
    setState(() => _consented = v);
    if (!v) {
      // auto-stop background when consent revoked
      await PlatformRunner.stopBackground();
      setState(() => _bgOn = false);
    }
  }

  Future<void> _toggleBackground(bool v) async {
    if (!_consented && v) return;
    if (v) {
      await _requestAndroidNotificationPermissionIfNeeded();
      await PlatformRunner.startBackground();
    } else {
      await PlatformRunner.stopBackground();
    }
    setState(() => _bgOn = v);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("GMF Settings")),
      body: ListView(
        children: [
          SwitchListTile(
            title: const Text("I consent to contribute compute (required)"),
            subtitle: const Text("No consent = no work. You can revoke anytime."),
            value: _consented,
            onChanged: _toggleConsent,
          ),
          const Divider(),
          SwitchListTile(
            title: const Text("Background 24/7 (Android: Foreground Service)"),
            subtitle: const Text("Runs only while charging + unmetered Wi-Fi; shows a persistent notification."),
            value: _bgOn,
            onChanged: _consented ? _toggleBackground : null,
          ),
          const Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              "Note: iOS cannot truly run 24/7 in background. Android can (with visible notification).",
            ),
          )
        ],
      ),
    );
  }
}
