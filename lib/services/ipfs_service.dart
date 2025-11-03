// lib/services/ipfs_service.dart

import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

class IpfsService {
  late WebViewController _webViewController;
  final Completer<WebViewController> _controllerCompleter = Completer();
  bool _isReady = false;

  IpfsService() {
    _initPlatform();
  }

  void _initPlatform() {
    if (WebView.platform == null && !kIsWeb) {
      WebView.platform = SurfaceAndroidWebView();
    }
  }

  /// Returns a WebView to embed in your UI (hidden or visible)
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
          name: 'Logger',
          onMessageReceived: (JavascriptMessage message) {
            if (kDebugMode) debugPrint('IPFS: ${message.message}');
          },
        ),
        JavascriptChannel(
          name: 'IpfsBridge',
          onMessageReceived: (JavascriptMessage message) {
            _handleBridgeMessage(message.message);
          },
        ),
      },
      gestureRecognizers: const <Factory<OneSequenceGestureRecognizer>>{
        Factory<OneSequenceGestureRecognizer>(() => EagerGestureRecognizer()),
      },
    );
  }

  /// Ensure IPFS node is ready
  Future<void> _ensureReady() async {
    if (_isReady) return;
    await _controllerCompleter.future;
    // Wait for JS to signal readiness
    await Future.delayed(const Duration(seconds: 2));
    _isReady = true;
  }

  /// Fetch and parse a JSON object from IPFS by CID
  Future<Map<String, dynamic>> fetchJson(String cid) async {
    await _ensureReady();
    final result = await _webViewController.runJavaScriptReturningResult(
      'window.ipfs.fetchJson("$cid")',
    );
    final jsonString = _cleanJsResult(result);
    if (jsonString.isEmpty) {
      throw Exception('Empty response from IPFS for CID: $cid');
    }
    return jsonDecode(jsonString) as Map<String, dynamic>;
  }

  /// Fetch raw text from IPFS by CID
  Future<String> fetchText(String cid) async {
    await _ensureReady();
    final result = await _webViewController.runJavaScriptReturningResult(
      'window.ipfs.fetchText("$cid")',
    );
    return _cleanJsResult(result);
  }

  /// Publish a message to an IPFS PubSub topic
  Future<void> pubsubPublish(String topic, String message) async {
    await _ensureReady();
    await _webViewController.runJavaScript(
      'window.ipfs.pubsubPublish("$topic", "$message")',
    );
  }

  /// Subscribe to an IPFS PubSub topic
  Stream<String> pubsubSubscribe(String topic) async* {
    await _ensureReady();
    // In a real app, this would use a JS channel callback
    // For now, simulate with periodic fetches
    // Full implementation requires JS event listener
    throw UnimplementedError('PubSub subscribe not yet implemented');
  }

  /// Clean JS result (remove quotes, handle null)
  String _cleanJsResult(dynamic result) {
    if (result == null) return '';
    String str = result.toString();
    // Remove surrounding quotes if present
    if (str.startsWith('"') && str.endsWith('"')) {
      str = str.substring(1, str.length - 1);
    }
    // Replace escaped quotes
    return str.replaceAll(r'\"', '"').replaceAll(r'\n', '\n');
  }

  void _handleBridgeMessage(String message) {
    // Handle events from JS (e.g., "nodeReady", "error")
    if (kDebugMode) debugPrint('IPFS Bridge: $message');
  }
}
// Add to IpfsService class
final StreamController<String> _pubsubController = StreamController.broadcast();

Stream<String> pubsubSubscribe(String topic) {
  _ensureReady().then((_) {
    _webViewController.runJavaScript('window.ipfs.pubsubSubscribe("$topic", () => {})');
  });
  return _pubsubController.stream;
}

void _handleBridgeMessage(String message) {
  try {
    final data = jsonDecode(message);
    if (data['type'] == 'pubsub') {
      _pubsubController.add(data['message'] as String);
    }
  } catch (e) {
    // Not a PubSub message — ignore
  }
}