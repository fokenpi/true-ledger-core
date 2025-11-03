// lib/services/plugin_loader.dart

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import '../models/plugin_manifest.dart';
import 'ipfs_service.dart';

class PluginLoader {
  final String pluginCid;
  final IpfsService ipfsService;
  late WebViewController _webViewController;
  final Completer<WebViewController> _controllerCompleter = Completer();

  PluginLoader({
    required this.pluginCid,
    required this.ipfsService,
  });

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
      final manifestJson = await ipfsService.fetchJson('$pluginCid/manifest.json');
      final manifest = PluginManifest.fromJson(manifestJson);

      // 2. Fetch plugin entry point (e.g., index.js)
      final pluginCode = await ipfsService.fetchText('$pluginCid/${manifest.entryPoint}');

      // 3. Execute plugin in isolated context
      await _webViewController.runJavaScript('''
        (function() {
          try {
            const pluginCode = `${pluginCode.replaceAll('`', '\\`')}`;
            (0, eval)(pluginCode);
          } catch (e) {
            window.FlutterBridge.postMessage(JSON.stringify({
              type: 'pluginError',
              error: e.message,
              stack: e.stack
            }));
          }
        })();
      ''');

      debugPrint('✅ Plugin loaded: ${manifest.name} ($pluginCid)');
    } catch (e, stack) {
      debugPrint('❌ Failed to load plugin $pluginCid: $e\n$stack');
    }
  }

  void _handlePluginMessage(String message) {
    try {
      final data = jsonDecode(message);
      final type = data['type'] as String?;

      switch (type) {
        case 'registerRoute':
          // Forward to app router (implement in your main app)
          debugPrint('Plugin requests route: ${data['path']}');
          break;
        case 'pluginError':
          debugPrint('Plugin runtime error: ${data['error']}');
          break;
        default:
          debugPrint('Unknown plugin message: $message');
      }
    } catch (e) {
      debugPrint('Invalid plugin message format: $message');
    }
  }
}