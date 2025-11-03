// lib/services/plugin_loader.dart

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import '../models/plugin_manifest.dart';

class PluginLoader {
  late WebViewController _webViewController;
  final Completer<WebViewController> _controllerCompleter = Completer();
  final String _pluginCid;

  PluginLoader(this._pluginCid);

  WebView buildWebView() {
    return WebView(
      initialUrl: 'about:blank',
      javascriptMode: JavascriptMode.unrestricted,
      onWebViewCreated: (WebViewController controller) {
        _webViewController = controller;
        _controllerCompleter.complete(controller);
        _loadPlugin();
      },
      javascriptChannels: {
        JavascriptChannel(
          name: 'FlutterBridge',
          onMessageReceived: (JavascriptMessage message) {
            _handlePluginMessage(message.message);
          },
        ),
      },
    );
  }

  Future<void> _loadPlugin() async {
    await _controllerCompleter.future;

    try {
      // 1. Fetch manifest from IPFS
      final manifestJson = await _fetchFromIpfs('$_pluginCid/manifest.json');
      final manifest = PluginManifest.fromJson(manifestJson);

      // 2. Fetch plugin entry point
      final pluginCode = await _fetchFromIpfs('$_pluginCid/${manifest.entryPoint}');

      // 3. Execute plugin
      await _webViewController.runJavaScript('''
        (function() {
          try {
            ${pluginCode.replaceAll('`', '\\`')}
          } catch (e) {
            window.FlutterBridge.postMessage(JSON.stringify({
              type: 'pluginError',
              error: e.message
            }));
          }
        })();
      ''');

      print('✅ Plugin loaded: ${manifest.name}');
    } catch (e) {
      print('❌ Plugin load error: $e');
    }
  }

  // Simulated IPFS fetch — replace with real IpfsService call in production
  Future<Map<String, dynamic>> _fetchFromIpfs(String path) async {
    // In real app, this would call IpfsService
    // For now, simulate with mock data
    if (path.contains('manifest.json')) {
      return {
        'name': 'IFRS Accounting',
        'version': '1.0.0',
        'description': 'Double-entry ledger with IFRS compliance',
        'author': 'True Ledger Community',
        'entryPoint': 'index.js',
        'uiComponent': 'ledger_ui.js',
        'dataTypes': ['Transaction', 'Account'],
        'permissions': ['ipld:write', 'pubsub:/true-ledger/accounting'],
        'dependencies': {}
      };
    } else {
      return {};
    }
  }

  void _handlePluginMessage(String message) {
    print('Plugin message: $message');
    // Handle plugin-to-app communication
  }
}