class PluginLoader {
  Future<void> loadPlugin(String pluginCid) async {
    // 1. Fetch manifest.json from IPFS
    final manifest = await _fetchFromIpfs('$pluginCid/manifest.json');
    
    // 2. Load UI from IPFS into WebView
    await _webViewController.loadUrl('ipfs://$pluginCid/ui.html');
    
    // 3. Register data handlers
    // (Plugin logic runs in WebView, communicates via JS channels)
  }
}