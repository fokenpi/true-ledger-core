import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

class IpfsService {
  late WebViewController _webViewController;
  final Completer<WebViewController> _controllerCompleter = Completer();

  IpfsService() {
    _init();
  }

  void _init() {
    if (WebView.platform == null && !kIsWeb) {
      WebView.platform = SurfaceAndroidWebView();
    }
  }

  WebView get webView {
    return WebView(
      initialUrl: 'asset:///assets/ipfs_plugin_loader.html',
      javascriptMode: JavascriptMode.unrestricted,
      onWebViewCreated: (WebViewController controller) {
        _webViewController = controller;
        _controllerCompleter.complete(controller);
      },
      javascriptChannels: <JavascriptChannel>{
        JavascriptChannel(
          name: 'FlutterBridge',
          onMessageReceived: (JavascriptMessage message) {
            _handleMessage(message.message);
          },
        ),
      },
      gestureRecognizers: const <Factory<OneSequenceGestureRecognizer>>{
        Factory<OneSequenceGestureRecognizer>(() => EagerGestureRecognizer()),
      },
    );
  }

  Future<void> _ensureReady() async {
    await _controllerCompleter.future;
  }

  // Fetch JSON from IPFS
  Future<Map<String, dynamic>> fetchJson(String cid) async {
    await _ensureReady();
    final jsonStr = await _webViewController.runJavaScriptReturningResult(
      'window.ipfsFetchJson("$cid")',
    );
    return jsonDecode(jsonStr.toString()) as Map<String, dynamic>;
  }

  // Fetch raw text (e.g., JS plugin code)
  Future<String> fetchText(String cid) async {
    await _ensureReady();
    final result = await _webViewController.runJavaScriptReturningResult(
      'window.ipfsFetchText("$cid")',
    );
    return result.toString();
  }

  // Execute plugin code
  Future<void> executePlugin(String jsCode) async {
    await _ensureReady();
    await _webViewController.runJavaScript(
      'window.executePlugin(`${jsCode.replaceAll('`', '\\`')}`)',
    );
  }

  void _handleMessage(String message) {
    // Handle plugin messages (e.g., errors, UI registration)
    try {
      final data = jsonDecode(message);
      if (data['type'] == 'pluginError') {
        debugPrint('IPFS Plugin Error: ${data['error']}');
      }
    } catch (e) {
      debugPrint('Failed to parse plugin message: $message');
    }
  }
}