import 'dart:io';
import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';
import 'consent.dart';
import 'platform_runner.dart';
import 'device_register.dart';
import 'account_store.dart';
import 'account_api.dart';

class GmfSettingsPage extends StatefulWidget {
  const GmfSettingsPage({super.key});
  @override
  State<GmfSettingsPage> createState() => _GmfSettingsPageState();
}

class _GmfSettingsPageState extends State<GmfSettingsPage> {
  bool _consented = false;
  bool _bgOn = false;
  String _baseUrl = "";
  String? _token;
  String? _accountId;
  final _nameCtl = TextEditingController();
  final _baseUrlCtl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final ok = await ConsentStore.hasConsent();
    final baseUrl = await AccountStore.getBaseUrl();
    final token = await AccountStore.getToken();
    final accountId = await AccountStore.getAccountId();
    _baseUrlCtl.text = baseUrl;

    setState(() {
      _baseUrl = baseUrl;
      _token = token;
      _accountId = accountId;

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

  
  Future<void> _saveBaseUrl() async {
    final v = _baseUrlCtl.text.trim();
    if (v.isEmpty) return;
    await AccountStore.setBaseUrl(v);
    setState(() => _baseUrl = v);
  }

  Future<void> _createAccount() async {
    final name = _nameCtl.text.trim();
    final baseUrl = _baseUrlCtl.text.trim().isEmpty ? _baseUrl : _baseUrlCtl.text.trim();
    final res = await AccountApi.create(baseUrl: baseUrl, displayName: name.isEmpty ? "friend" : name);
    if (res["ok"] == true) {
      await AccountStore.setBaseUrl(baseUrl);
      await AccountStore.setToken(res["api_token"]);
      await AccountStore.setAccountId(res["account_id"]);
      setState(() {
        _baseUrl = baseUrl;
        _token = res["api_token"];
        _accountId = res["account_id"];
      });
    }
  }

  Future<void> _logout() async {
    await AccountStore.clear();
    setState(() { _token = null; _accountId = null; });
    await PlatformRunner.stopBackground();
    setState(() => _bgOn = false);
  }

  Future<void> _toggleBackground(bool v) async {
    if (!_consented && v) return;
    if (v) {
      await _requestAndroidNotificationPermissionIfNeeded();
      // ensure device is registered to this account before starting background
      // TODO: replace baseUrl/accountId with your real config/account system
      final baseUrl = const String.fromEnvironment('GMF_BASE_URL', defaultValue: 'http://10.0.2.2:8080');
      final accountId = const String.fromEnvironment('GMF_ACCOUNT_ID', defaultValue: 'demo');
      if (_token == null || _accountId == null) { throw Exception('no account/token'); }
      await DeviceRegister.ensureRegistered(baseUrl: baseUrl, token: _token!);
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
          ListTile(title: const Text('Server Base URL')),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: TextField(controller: _baseUrlCtl, decoration: const InputDecoration(hintText: 'http://host:8080')),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: ElevatedButton(onPressed: _saveBaseUrl, child: const Text('Save Base URL')),
          ),
          const Divider(),
          ListTile(title: const Text('Account')),
          if (_accountId != null) Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Text('account_id: '+_accountId!),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: TextField(controller: _nameCtl, decoration: const InputDecoration(hintText: 'display name (optional)')),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: ElevatedButton(onPressed: _createAccount, child: const Text('Create Account (get token)')),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: ElevatedButton(onPressed: _logout, child: const Text('Logout / Clear Token')),
          ),
          const Divider(),

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
