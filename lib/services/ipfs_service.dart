// lib/services/ipfs_service.dart

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

class IpfsService {
  late WebViewController _webViewController;
  final Completer<WebViewController> _controllerCompleter = Completer();

  IpfsService() {
    _initPlatform();
  }

  void _initPlatform() {
    if (WebView.platform == null && !kIsWeb) {
      WebView.platform = SurfaceAndroidWebView();
    }
  }

  WebView get webView {
    return WebView(
      initialUrl: 'asset:///assets/ipfs_worker.html',
      javascriptMode: JavascriptMode.unrestricted,
      onWebViewCreated: (WebViewController controller) {
        _webViewController = controller;
        _controllerCompleter.complete(controller);
      },
      javascriptChannels: {
        JavascriptChannel(
          name: 'FlutterBridge',
          onMessageReceived: (JavascriptMessage message) {
            // Handle messages from JS
          },
        ),
      },
    );
  }

  Future<void> _ensureReady() async {
    await _controllerCompleter.future;
  }

  Future<Map<String, dynamic>> fetchJson(String cid) async {
    await _ensureReady();
    final result = await _webViewController.runJavaScriptReturningResult(
      'window.ipfs.fetchJson("$cid")',
    );
    final jsonString = result.toString().replaceAll('"', '');
    return jsonDecode(jsonString) as Map<String, dynamic>;
  }

  Future<String> fetchText(String cid) async {
    await _ensureReady();
    final result = await _webViewController.runJavaScriptReturningResult(
      'window.ipfs.fetchText("$cid")',
    );
    return result.toString().replaceAll('"', '');
  }
}