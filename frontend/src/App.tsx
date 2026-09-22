import { HomePage } from "./pages/HomePage";
import "./index.css";

function App() {
  return (
    <div className="app-wrapper">
      {/* Header */}
      <header className="app-header">
        <div className="header-inner">
          <div className="logo">
            <div className="logo-icon">🛡️</div>
            <div>
              CivicShield
              <div className="logo-sub">e-Challan Fraud Detection</div>
            </div>
          </div>
          <div className="header-badge">Academic IDT Prototype</div>
        </div>
      </header>

      {/* Main content */}
      <main className="main-content">
        <HomePage />
      </main>

      {/* Footer */}
      <footer
        style={{
          borderTop: "1px solid var(--bg-border)",
          padding: "14px 24px",
          textAlign: "center",
          fontSize: "0.72rem",
          color: "var(--text-muted)",
        }}
      >
        CivicShield — Academic Design Engineering / IDT Prototype · Not for production use ·
        For official challan verification:{" "}
        <a
          href="https://echallan.parivahan.gov.in/"
          target="_blank"
          rel="noopener noreferrer"
        >
          echallan.parivahan.gov.in
        </a>
      </footer>
    </div>
  );
}

export default App;
