import 'dart:convert';
import 'package:uuid/uuid.dart';
import 'package:crypto/crypto.dart' show sha256;

import 'api.dart';
import 'device_keys.dart';
import 'sigmsg_v1.dart';

String _sha256HexBytes(List<int> b) => sha256.convert(b).toString();

/// bundle_v1: header_bytes at start (must fit into chunk0)
List<int> buildBundleV1({
  required String mainLean,
  required String buildLog,
  required String versionsJson,
}) {
  final mainBytes = utf8.encode(mainLean);
  final logBytes = utf8.encode(buildLog);
  final verBytes = utf8.encode(versionsJson);

  final headerObj = {
    "kind": "gmf_trace_bundle_header",
    "version": 1,
    "format": "gmf_bundle_v1",
    "files": [
      {"name": "Main.lean", "sha256": _sha256HexBytes(mainBytes), "bytes": mainBytes.length},
      {"name": "build.log", "sha256": _sha256HexBytes(logBytes), "bytes": logBytes.length},
      {"name": "versions.json", "sha256": _sha256HexBytes(verBytes), "bytes": verBytes.length},
    ]
  };
  final headerBytes = utf8.encode(jsonEncode(headerObj));

  // body: simple separators (server不需要解析body，只抽查一致性；header 已鎖 required files)
  final sep = utf8.encode("\n---\n");
  return <int>[
    ...headerBytes,
    ...sep, ...mainBytes,
    ...sep, ...logBytes,
    ...sep, ...verBytes,
  ];
}

/// naive merkle (same as agent/server): leaf=sha256(chunk), parent=sha256(left||right), odd duplicate last
List<List<List<int>>> buildMerkleLevels(List<List<int>> leaves32) {
  final levels = <List<List<int>>>[];
  levels.add(List.of(leaves32));
  while (levels.last.length > 1) {
    final cur = levels.last;
    final nxt = <List<int>>[];
    for (int i = 0; i < cur.length; i += 2) {
      final left = cur[i];
      final right = (i + 1 < cur.length) ? cur[i + 1] : cur[i];
      final parent = sha256.convert(<int>[...left, ...right]).bytes;
      nxt.add(parent);
    }
    levels.add(nxt);
  }
  return levels;
}

List<Map<String, dynamic>> merkleProof(List<List<List<int>>> levels, int idx) {
  final proof = <Map<String, dynamic>>[];
  int i = idx;
  for (int lvl = 0; lvl < levels.length - 1; lvl++) {
    final cur = levels[lvl];
    final isRight = (i % 2 == 1);
    final sibIdx = isRight ? i - 1 : i + 1;
    final sib = (sibIdx < cur.length) ? cur[sibIdx] : cur[i];
    proof.add({
      "side": isRight ? "L" : "R",
      "h": _sha256HexBytes(sib),
    });
    i = i ~/ 2;
  }
  return proof;
}

/// deterministic audit indices same rule as server: always include 0, rest from sha256(seed||i) mod n excluding 0 if possible
List<int> auditIndices({required String seedHex, required int n, required int k}) {
  if (n <= 0) return [0];
  final out = <int>[0];
  final seen = <int>{0};
  final need = (k <= 1) ? 0 : (k - 1);
  final tries = (need * 5).clamp(1, 10_000);
  final seedBytes = List<int>.generate(seedHex.length ~/ 2, (i) => int.parse(seedHex.substring(i * 2, i * 2 + 2), radix: 16));
  for (int i = 0; i < tries && out.length < 1 + need; i++) {
    final msg = <int>[...seedBytes, ...[(i >> 24) & 255, (i >> 16) & 255, (i >> 8) & 255, i & 255]];
    final h = sha256.convert(msg).bytes;
    final x = (h[0] << 56) | (h[1] << 48) | (h[2] << 40) | (h[3] << 32) | (h[4] << 24) | (h[5] << 16) | (h[6] << 8) | (h[7]);
    final idx = (x.abs() % n);
    if (idx != 0 && !seen.contains(idx)) {
      seen.add(idx);
      out.add(idx);
    }
  }
  while (out.length < 1 + need) out.add(0);
  return out;
}

class MobileRunner {
  final GmfApi api;
  final String enrollToken;
  final String topics;
  final String platform; // "ios" / "android"
  final String deviceId;

  MobileRunner({
    required this.api,
    required this.enrollToken,
    required this.topics,
    required this.platform,
    required this.deviceId,
  });

  static Future<String> ensureDeviceId() async {
    // simplest: random uuid (you can persist with SharedPreferences if you want)
    return const Uuid().v4();
  }

  /// one cycle: register -> lease -> compute -> audit -> sign -> submit
  Future<void> runOnce() async {
    final kp = await DeviceKeys.loadOrCreate();
    final pkHex = await DeviceKeys.pubkeyHex(kp);

    await api.deviceRegister(
      deviceId: deviceId,
      platform: platform,
      topics: topics,
      enrollToken: enrollToken,
      pubkeyHex: pkHex,
    );

    final lease = await api.lease(deviceId: deviceId, topics: topics);
    final jobId = lease['job_id'] as String;
    final leaseId = lease['lease_id'] as String;

    final policyHash = (lease['server_asserted_policy_hash'] ?? lease['policy_hash'] ?? '') as String;
    final sigSpecHash = (lease['sig_spec_hash'] ?? '') as String;
    final nonce = (lease['challenge_nonce'] ?? '') as String;

    final auditRequired = (lease['audit_required'] ?? false) as bool;
    final auditSpec = (lease['audit_spec'] ?? {}) as Map<String, dynamic>;
    final chunkSize = (auditSpec['chunk_size'] ?? 65536) as int;
    final sampleK = (auditSpec['sample_k'] ?? 3) as int;
    final seedHex = (auditSpec['seed_hex'] ?? '') as String;

    // Placeholder math output (deterministic): sha256(canonical input)
    final input = lease['input'];
    final canon = jsonEncode(input);
    final output = "gmf_mobile_placeholder:sha256=${sha256.convert(utf8.encode(canon)).toString()}";

    // Create a tiny Bundle v1 (header in chunk0) so audited jobs can be verified.
    final mainLean = "import Mathlib\n-- placeholder proof artifact\n-- job_id=$jobId\n-- lease_id=$leaseId\n";
    final buildLog = "mobile: no-lean-compile (placeholder)\n";
    final versions = jsonEncode({
      "agent": "gmf_mobile_flutter",
      "platform": platform,
      "note": "placeholder bundle; replace with real proof artifacts later",
    });

    final bundleBytes = buildBundleV1(mainLean: mainLean, buildLog: buildLog, versionsJson: versions);
    final headerBytes = utf8.encode(jsonEncode({
      "kind":"gmf_trace_bundle_header","version":1,"format":"gmf_bundle_v1"
    }));
    final headerSha256 = _sha256HexBytes(headerBytes); // minimal header sha; if你要嚴格，就用真正 headerObj bytes（buildBundleV1 裡那份）

    String merkleRootHex = '';
    int numChunks = 0;
    List<Map<String, dynamic>> samples = [];

    if (auditRequired) {
      final chunks = <List<int>>[];
      for (int i = 0; i < bundleBytes.length; i += chunkSize) {
        chunks.add(bundleBytes.sublist(i, (i + chunkSize).clamp(0, bundleBytes.length)));
      }
      if (chunks.isEmpty) chunks.add(<int>[]);

      numChunks = chunks.length;
      final leaves = chunks.map((c) => sha256.convert(c).bytes).toList();
      final levels = buildMerkleLevels(leaves);
      merkleRootHex = _sha256HexBytes(levels.last.first);

      final idxs = auditIndices(seedHex: seedHex, n: numChunks, k: sampleK);

      samples = idxs.map((idx) {
        final c = chunks[idx];
        final proof = merkleProof(levels, idx);
        return {
          "idx": idx,
          "chunk_b64": base64Encode(c),
          "proof": proof,
        };
      }).toList();
    }

    // Build signature message (sigmsg_v1)
    final sampleIndices = samples.map((e) => e['idx'] as int).toList();
    final sigBytes = sigmsgV1Bytes(
      deviceId: deviceId,
      leaseId: leaseId,
      jobId: jobId,
      policyHash: policyHash,
      sigSpecHash: sigSpecHash,
      challengeNonce: nonce,
      bundleFormat: "gmf_bundle_v1",
      headerSha256: headerSha256,
      merkleRootHex: merkleRootHex,
      numChunks: numChunks,
      sampleIndices: sampleIndices,
      output: output,
    );
    final sigB64 = await DeviceKeys.signB64(kp, sigBytes);

    final payload = <String, dynamic>{
      "device_id": deviceId,
      "job_id": jobId,
      "lease_id": leaseId,
      "output": output,

      "policy_hash": policyHash,
      "sig_spec_hash": sigSpecHash,

      "challenge_nonce": nonce,

      "bundle_format": "gmf_bundle_v1",
      "header_sha256": headerSha256,

      if (auditRequired) ...{
        "merkle_root_hex": merkleRootHex,
        "num_chunks": numChunks,
        "samples": samples,
      },

      "device_sig_alg": "ed25519",
      "device_sig": sigB64,
    };

    await api.submit(payload);
  }
}
