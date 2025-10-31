import 'package:webview_flutter/webview_flutter.dart';

class IpfsService {
  late WebViewController _webViewController;

  Future<void> init() async {
    _webViewController = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setNavigationDelegate(
        NavigationDelegate(onPageFinished: (String url) async {
          // js-ipfs is ready
        }),
      )
      ..loadFlutterAsset('assets/ipfs_worker.html');
  }

  Future<String> addJson(Map<String, dynamic> data) async {
    final json = jsonEncode(data);
    final cid = await _webViewController.runJavaScriptReturningResult(
      'window.ipfs.addJson($json)',
    );
    return cid.toString();
  }

  Future<void> pubsubPublish(String topic, String cid) async {
    await _webViewController.runJavaScript(
      'window.ipfs.pubsub.publish("$topic", "$cid")',
    );
  }

  Stream<String> pubsubSubscribe(String topic) {
    // Use JavaScript channel to receive messages
    // (Implementation omitted for brevity)
  }
}