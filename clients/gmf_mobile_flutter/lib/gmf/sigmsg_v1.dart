import 'dart:convert';
import 'package:crypto/crypto.dart' show sha256;

String sha256HexOfUtf8(String s) {
  final bytes = utf8.encode(s);
  final digest = sha256.convert(bytes);
  return digest.toString();
}

/// GMF sigmsg_v1 canonical bytes (UTF-8 lines `key=value\n`)
/// Keys order must match ledger/policies/sig_spec_v1.md
List<int> sigmsgV1Bytes({
  required String deviceId,
  required String leaseId,
  required String jobId,
  required String policyHash,
  required String sigSpecHash,
  required String challengeNonce,
  required String bundleFormat,
  required String headerSha256,
  required String merkleRootHex,
  required int numChunks,
  required List<int> sampleIndices,
  required String output,
}) {
  final outputSha256 = sha256HexOfUtf8(output);
  final sampleIdx = sampleIndices.isEmpty ? '' : sampleIndices.join(',');

  final kv = <String, String>{
    'device_id': deviceId,
    'lease_id': leaseId,
    'job_id': jobId,
    'policy_hash': policyHash,
    'sig_spec_hash': sigSpecHash,
    'challenge_nonce': challengeNonce,
    'bundle_format': bundleFormat,
    'header_sha256': headerSha256,
    'merkle_root_hex': merkleRootHex,
    'num_chunks': numChunks.toString(),
    'sample_indices': sampleIdx,
    'output_sha256': outputSha256,
  };

  const keysInOrder = [
    'device_id',
    'lease_id',
    'job_id',
    'policy_hash',
    'sig_spec_hash',
    'challenge_nonce',
    'bundle_format',
    'header_sha256',
    'merkle_root_hex',
    'num_chunks',
    'sample_indices',
    'output_sha256',
  ];

  final sb = StringBuffer();
  for (final k in keysInOrder) {
    sb.write(k);
    sb.write('=');
    sb.write(kv[k] ?? '');
    sb.write('\n');
  }
  return utf8.encode(sb.toString());
}
