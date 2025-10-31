import 'package:pointycastle/export.dart';

class IdentityService {
  String? _did;
  String? _privateKey;

  Future<void> generateIdentity() async {
    // Generate secp256k1 keypair
    // Create did:key (e.g., did:key:z6Mk...)
    // Store private key in Hive (encrypted)
  }

  String get did => _did!;
  String sign(String payload) { /* ECDSA sign */ }
}