// lib/main.dart

import 'package:flutter/material.dart';
import 'package:true_ledger_core/services/ipfs_service.dart';
import 'package:true_ledger_core/services/plugin_loader.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const TrueLedgerApp());
}

class TrueLedgerApp extends StatelessWidget {
  const TrueLedgerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'True Ledger Core',
      theme: ThemeData(
        primarySwatch: Colors.green,
        useMaterial3: true,
      ),
      home: const PluginHostScreen(),
    );
  }
}

class PluginHostScreen extends StatefulWidget {
  const PluginHostScreen({super.key});

  @override
  State<PluginHostScreen> createState() => _PluginHostScreenState();
}

class _PluginHostScreenState extends State<PluginHostScreen> {
  late IpfsService _ipfs;
  WebView? _pluginWebView;

  @override
  void initState() {
    super.initState();
    _ipfs = IpfsService();
    
    // Example: Load IFRS Accounting plugin (replace with real CID)
    final loader = PluginLoader(
      pluginCid: 'QmIFRSAccountingPluginCID', // ← Replace with real plugin CID
      ipfsService: _ipfs,
    );
    _pluginWebView = loader.buildWebView();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('True Ledger Core')),
      body: Column(
        children: [
          // Main content area (your app UI)
          Expanded(
            child: Center(
              child: Text(
                'Plugin Host Ready\nIPFS Bridge Active',
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 18),
              ),
            ),
          ),
          // Hidden WebView for IPFS/Plugin execution
          SizedBox(
            height: 1,
            width: 1,
            child: _pluginWebView,
          ),
        ],
      ),
    );
  }
}