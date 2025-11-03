// lib/services/plugin_verifier.dart

import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/digests/sha256.dart';

class PluginVerifier {
  static bool verifySignature({
    required Map<String, dynamic> manifest,
    required String signatureBase64,
    required String publicKeyBase64,
  }) {
    try {
      // 1. Canonicalize manifest (sort keys, no whitespace)
      final canonical = _canonicalJson(manifest);
      
      // 2. Hash the manifest
      final digest = SHA256Digest().process(utf8.encode(canonical));
      
      // 3. Decode public key
      final pubBytes = base64Decode(publicKeyBase64);
      final ecParams = ECCurve_secp256k1();
      final pubKey = ECPublicKey(ecParams.curve.decodePoint(pubBytes), ecParams);
      
      // 4. Decode signature
      final sigBytes = base64Decode(signatureBase64);
      final half = sigBytes.length ~/ 2;
      final r = _bytesToBigInt(sigBytes.sublist(0, half));
      final s = _bytesToBigInt(sigBytes.sublist(half));
      final signature = ECSignature(r, s);
      
      // 5. Verify
      final verifier = ECDSASigner(null, HMac(SHA256Digest(), 32));
      verifier.init(false, PublicKeyParameter(pubKey));
      return verifier.verifySignature(digest, signature);
    } catch (e) {
      print('⚠️ Signature verification failed: $e');
      return false;
    }
  }

  static String _canonicalJson(Map<String, dynamic> data) {
    // Simple canonicalization: sorted keys, no extra spaces
    final buffer = StringBuffer();
    buffer.write('{');
    final keys = data.keys.toList()..sort();
    for (int i = 0; i < keys.length; i++) {
      if (i > 0) buffer.write(',');
      final key = keys[i];
      final value = data[key];
      buffer.write('"$key":');
      if (value is String) {
        buffer.write('"$value"');
      } else if (value is num) {
        buffer.write(value.toString());
      } else if (value is bool) {
        buffer.write(value ? 'true' : 'false');
      } else if (value == null) {
        buffer.write('null');
      } else {
        buffer.write('"${value.toString()}"');
      }
    }
    buffer.write('}');
    return buffer.toString();
  }

  static BigInt _bytesToBigInt(Uint8List bytes) {
    return BigInt.parse(bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(), radix: 16);
  }
}