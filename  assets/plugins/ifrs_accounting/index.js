// Plugin entry point
window.pluginHost = {
  onLoad: (name) => {
    console.log(`Plugin loaded: ${name}`);

    // Register with main app
    window.PluginBridge.postMessage(JSON.stringify({
      type: 'registerRoute',
      path: '/ledger',
      component: 'AccountingUI'
    }));

    // Subscribe to transactions
    window.PluginBridge.postMessage(JSON.stringify({
      type: 'subscribe',
      topic: '/true-ledger/accounting'
    }));
  }
};