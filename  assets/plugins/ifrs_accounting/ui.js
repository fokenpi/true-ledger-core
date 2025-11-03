// IFRS Accounting UI
class IFRSLedgerUI {
  render(container) {
    container.innerHTML = `
      <div style="padding: 16px; font-family: Arial, sans-serif;">
        <h2>📊 IFRS Accounting Ledger</h2>
        <div id="balance-sheet">
          <h3>Balance Sheet</h3>
          <p>Loading...</p>
        </div>
        <div id="income-statement" style="margin-top: 20px;">
          <h3>Income Statement</h3>
          <p>Loading...</p>
        </div>
        <button id="refresh-btn" style="margin-top: 20px; padding: 8px 16px; background: #4CAF50; color: white; border: none; cursor: pointer;">
          Refresh Reports
        </button>
      </div>
    `;

    document.getElementById('refresh-btn').onclick = () => {
      this.updateReports();
    };

    this.updateReports();
  }

  updateReports() {
    if (window.trueLedger?.accounting) {
      const bs = window.trueLedger.accounting.getBalanceSheet();
      const is = window.trueLedger.accounting.getIncomeStatement();
      
      document.getElementById('balance-sheet').innerHTML = `
        <h3>Balance Sheet (${bs.date.split('T')[0]})</h3>
        <ul>
          <li><strong>Assets:</strong> ${bs.assets.toFixed(2)}</li>
          <li><strong>Liabilities:</strong> ${bs.liabilities.toFixed(2)}</li>
          <li><strong>Equity:</strong> ${bs.equity.toFixed(2)}</li>
        </ul>
      `;
      
      document.getElementById('income-statement').innerHTML = `
        <h3>Income Statement (${is.period})</h3>
        <ul>
          <li><strong>Revenue:</strong> ${is.revenue.toFixed(2)}</li>
          <li><strong>Expenses:</strong> ${is.expenses.toFixed(2)}</li>
          <li><strong>Net Income:</strong> ${is.netIncome.toFixed(2)}</li>
        </ul>
      `;
    }
  }
}

// Register UI component
if (window.FlutterBridge) {
  window.FlutterBridge.postMessage(JSON.stringify({
    type: 'registerUI',
    name: 'IFRSLedgerUI',
    component: 'IFRSLedgerUI'
  }));
}

// Make globally available
window.IFRSLedgerUI = IFRSLedgerUI;