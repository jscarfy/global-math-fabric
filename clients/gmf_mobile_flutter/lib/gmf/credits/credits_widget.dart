import 'package:flutter/material.dart';
import 'device_identity.dart';
import 'claim.dart';
import 'relay_client.dart';
import 'pages_ledger.dart';

class CreditsWidget extends StatefulWidget {
  final String relayBaseUrl; // e.g. http://localhost:8787 or https://your-relay
  const CreditsWidget({super.key, required this.relayBaseUrl});

  @override
  State<CreditsWidget> createState() => _CreditsWidgetState();
}

class _CreditsWidgetState extends State<CreditsWidget> {
  final store = DeviceIdentityStore();
  final pages = PagesLedger();
  DeviceIdentity? id;
  int todayCredits = 0;
  String status = "";

  String _todayUtc() {
    final d = DateTime.now().toUtc();
    String two(int x)=>x.toString().padLeft(2,'0');
    return "${d.year}-${two(d.month)}-${two(d.day)}";
  }

  Future<void> refresh() async {
    final ident = await store.loadOrCreate();
    final date = _todayUtc();
    final c = await pages.creditsForDeviceOnDate(date, ident.deviceIdHex);
    setState(() {
      id = ident;
      todayCredits = c;
    });
  }

  Future<void> sendTestClaim() async {
    final ident = await store.loadOrCreate();
    final payload = makeClaimPayload(
      taskId: "mvp-test",
      cpuMs: 30_000,  // 30s
      gpuMs: 0,
      artifacts: const [],
    );
    final sig = await signClaimPayloadB64(
      claimPayload: payload,
      devicePrivSeedB64: ident.devicePrivKeyB64,
    );
    final relay = RelayClient(widget.relayBaseUrl);
    setState(() => status = "posting claim…");
    final ssr = await relay.postClaim(
      claimPayload: payload,
      devicePubB64: ident.devicePubKeyB64,
      deviceSigB64: sig,
    );
    setState(() => status = "SSR received (server signed). You will see credits after SSR is published to Pages.");
    // credits show after SSR jsonl gets copied to releases/ledger/ssr (daily job or manual)
    await Future.delayed(const Duration(milliseconds: 300));
    await refresh();
  }

  @override
  void initState() {
    super.initState();
    refresh();
  }

  @override
  Widget build(BuildContext context) {
    final ident = id;
    return Scaffold(
      appBar: AppBar(title: const Text("Credits")),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text("Device ID:", style: Theme.of(context).textTheme.titleMedium),
            SelectableText(ident?.deviceIdHex ?? "loading…"),
            const SizedBox(height: 12),
            Text("Today (microcredits): $todayCredits"),
            const SizedBox(height: 12),
            ElevatedButton(
              onPressed: sendTestClaim,
              child: const Text("Send test claim (30s CPU)"),
            ),
            const SizedBox(height: 8),
            ElevatedButton(
              onPressed: refresh,
              child: const Text("Refresh from Pages"),
            ),
            const SizedBox(height: 12),
            Text(status),
          ],
        ),
      ),
    );
  }
}
