// lib/services/plugin_loader.dart

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
      // Fetch manifest
      final manifestJson = await ipfsService.fetchJson('$pluginCid/manifest.json');
      final manifest = PluginManifest.fromJson(manifestJson);

      // Fetch plugin code
      final pluginCode = await ipfsService.fetchText('$pluginCid/${manifest.entryPoint}');

      // Execute in sandbox
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

      debugPrint('✅ Plugin loaded: ${manifest.name}');
    } catch (e) {
      debugPrint('❌ Plugin load error: $e');
    }
  }

  void _handlePluginMessage(String message) {
    // Handle plugin-to-app communication
  }
}