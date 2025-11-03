// lib/services/plugin_loader.dart

import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import '../models/plugin_manifest.dart';
import 'ipfs_service.dart';
import 'plugin_verifier.dart';

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
      // 1. Fetch manifest, signature, and public key from IPFS
      final manifestJson = await ipfsService.fetchJson('$pluginCid/manifest.json');
      final signature = (await ipfsService.fetchText('$pluginCid/signature.sig')).trim();
      final publicKey = (await ipfsService.fetchText('$pluginCid/public.key')).trim();

      // 2. Verify plugin signature
      if (!PluginVerifier.verifySignature(
        manifest: manifestJson,
        signatureBase64: signature,
        publicKeyBase64: publicKey,
      )) {
        throw Exception('Plugin signature verification failed for $pluginCid');
      }

      // 3. Parse manifest
      final manifest = PluginManifest.fromJson(manifestJson);

      // 4. Fetch plugin entry point (e.g., index.js)
      final pluginCode = await ipfsService.fetchText('$pluginCid/${manifest.entryPoint}');

      // 5. Execute plugin in isolated context
      await _webViewController.runJavaScript('''
        (function() {
          try {
            const code = `${pluginCode.replaceAll('`', '\\`')}`;
            (0, eval)(code);
          } catch (e) {
            window.FlutterBridge.postMessage(JSON.stringify({
              type: 'pluginError',
              error: e.message,
              stack: e.stack?.toString() || ''
            }));
          }
        })();
      ''');

      debugPrint('✅ Trusted plugin loaded: ${manifest.name} ($pluginCid)');
    } catch (e, stack) {
      debugPrint('❌ Plugin load failed: $e\n$stack');
    }
  }

  void _handlePluginMessage(String message) {
    try {
      final data = jsonDecode(message);
      final type = data['type'] as String?;

      switch (type) {
        case 'registerRoute':
          debugPrint('Plugin requests route: ${data['path']}');
          // Forward to app router (implement in main app)
          break;
        case 'pluginError':
          debugPrint('Plugin runtime error: ${data['error']}');
          break;
        default:
          debugPrint('Unknown plugin message: $message');
      }
    } catch (e) {
      debugPrint('Invalid plugin message: $message');
    }
  }
}