import 'package:flutter/material.dart';
import 'runtime_status.dart';
import 'platform_runner.dart';

class StatusScreen extends StatelessWidget {
  const StatusScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("GMF Status")),
      body: ValueListenableBuilder(
        valueListenable: RuntimeStatus.notifier,
        builder: (context, snap, _) {
          final text = _renderText(snap.status, snap.detail);
          return Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(text, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
                const SizedBox(height: 12),
                const Text("You can Pause/Resume anytime. Consent can be revoked in Settings."),
                const Spacer(),
                Row(
                  children: [
                    Expanded(
                      child: ElevatedButton(
                        onPressed: () async => PlatformRunner.startBackground(),
                        child: const Text("Resume"),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: OutlinedButton(
                        onPressed: () async => PlatformRunner.stopBackground(),
                        child: const Text("Pause"),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  String _renderText(GMFStatus s, String d) {
    switch (s) {
      case GMFStatus.running: return d.isEmpty ? "Running" : "Running — $d";
      case GMFStatus.paused: return "Paused";
      case GMFStatus.starting: return "Starting…";
      case GMFStatus.blockedNoConsent: return "Blocked — consent missing";
      case GMFStatus.blockedNoToken: return "Blocked — token missing";
      case GMFStatus.blockedNotCharging: return "Blocked — not charging";
      case GMFStatus.blockedNotWifi: return "Blocked — not on Wi-Fi/Ethernet";
      case GMFStatus.stopped: return d.isEmpty ? "Stopped" : "Stopped — $d";
    }
  }
}
