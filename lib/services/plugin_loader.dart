import 'dart:async';
import 'package:flutter/services.dart';
import 'package:webview_flutter/webview_flutter.dart';
import '../models/plugin_manifest.dart';

class PluginLoader {
  late WebViewController _webViewController;
  final Map<String, PluginManifest> _loadedPlugins = {};

  PluginLoader();

  Future<void> initWebView(BuildContext context) async {
    if (WebView.platform == null && !kIsWeb) {
      WebView.platform = SurfaceAndroidWebView();
    }
  }

  WebView buildWebView() {
    return WebView(
      initialUrl: 'about:blank',
      javascriptMode: JavascriptMode.unrestricted,
      onWebViewCreated: (WebViewController controller) {
        _webViewController = controller;
      },
      javascriptChannels: {
        JavascriptChannel(
          name: 'PluginBridge',
          onMessageReceived: (JavascriptMessage message) {
            // Handle plugin messages (e.g., "registerUI", "requestData")
            _handlePluginMessage(message.message);
          },
        ),
      },
    );
  }

  Future<void> loadPluginFromIpfs(String pluginCid) async {
    try {
      // 1. Fetch manifest
      final manifest = await PluginManifest.fromIpfs(pluginCid);
      _loadedPlugins[pluginCid] = manifest;

      // 2. Load plugin entry point in WebView
      await _webViewController.loadUrl('ipfs://$pluginCid/${manifest.entryPoint}');

      // 3. Notify plugin it's loaded
      await _webViewController.runJavaScript(
        'window.pluginHost.onLoad("${manifest.name}")',
      );

      print('✅ Plugin loaded: ${manifest.name} ($pluginCid)');
    } catch (e) {
      print('❌ Failed to load plugin: $e');
    }
  }

  void _handlePluginMessage(String message) {
    // Parse JSON message from plugin
    // Example: { "type": "registerRoute", "path": "/ledger", "component": "LedgerUI" }
    // Forward to main app router
  }

  List<PluginManifest> get loadedPlugins => _loadedPlugins.values.toList();
}