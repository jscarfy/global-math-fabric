import 'package:flutter/material.dart';
import 'consent_store.dart';

class ConsentScreen extends StatefulWidget {
  const ConsentScreen({super.key});
  @override
  State<ConsentScreen> createState() => _ConsentScreenState();
}

class _ConsentScreenState extends State<ConsentScreen> {
  bool _checked = false;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Global Math Fabric Consent")),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              "Before contributing compute in the background, you must explicitly consent.\n\n"
              "Hard guarantees:\n"
              "• You can Pause/Stop anytime.\n"
              "• Contribution status stays visible (notification/tray).\n"
              "• No scanning of your personal files.\n"
              "• Resource caps (charging/network/CPU) are enforced.\n",
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Checkbox(value: _checked, onChanged: (v) => setState(() => _checked = v ?? false)),
                const Expanded(child: Text("I understand and I consent to background contribution on this device.")),
              ],
            ),
            const Spacer(),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton(
                    onPressed: _checked
                        ? () async {
                            await ConsentStore.grant();
                            if (context.mounted) Navigator.of(context).pop(true);
                          }
                        : null,
                    child: const Text("Agree & Continue"),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            const Text(
              "You can revoke consent later in Settings.",
              style: TextStyle(fontSize: 12, color: Colors.grey),
            ),
          ],
        ),
      ),
    );
  }
}
