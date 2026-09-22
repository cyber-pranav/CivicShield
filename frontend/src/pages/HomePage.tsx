import { useState } from "react";
import type { AnalysisResult, DemoCase } from "../types/analysis";
import { analyzeText, analyzeFile, ApiError } from "../api/analyzeApi";
import { InputPanel } from "../components/InputPanel";
import { DemoSelector } from "../components/DemoSelector";
import { LimitationDisclaimer } from "../components/LimitationDisclaimer";
import { ResultPage } from "./ResultPage";

export function HomePage() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [demoLabel, setDemoLabel] = useState<string | null>(null);

  const handleSubmitText = async (inputType: "url" | "text", content: string) => {
    setLoading(true);
    setError(null);
    setDemoLabel(null);
    try {
      const res = await analyzeText(inputType, content);
      setResult(res);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`Analysis failed (${err.status}): ${err.message}`);
      } else {
        setError("Could not connect to the backend. Is the server running on port 8000?");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSubmitFile = async (inputType: "image" | "pdf", file: File) => {
    setLoading(true);
    setError(null);
    setDemoLabel(null);
    try {
      const res = await analyzeFile(inputType, file);
      setResult(res);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`Analysis failed (${err.status}): ${err.message}`);
      } else {
        setError("Could not connect to the backend. Is the server running on port 8000?");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleDemo = async (demo: DemoCase) => {
    setLoading(true);
    setError(null);
    setDemoLabel(demo.label);
    try {
      const res = await analyzeText(
        demo.inputType as "url" | "text",
        demo.content
      );
      setResult(res);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`Demo failed (${err.status}): ${err.message}`);
      } else {
        setError("Could not connect to the backend. Is the server running on port 8000?");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setResult(null);
    setError(null);
    setDemoLabel(null);
  };

  if (result) {
    return (
      <div>
        {demoLabel && (
          <div
            style={{
              background: "rgba(245,158,11,0.1)",
              border: "1px solid rgba(245,158,11,0.3)",
              borderRadius: "8px",
              padding: "8px 14px",
              marginBottom: 16,
              fontSize: "0.78rem",
              color: "#fbbf24",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <span>⚠️</span>
            <strong>SYNTHETIC TEST CASE:</strong> {demoLabel} — not a real government notice.
          </div>
        )}
        <ResultPage result={result} onReset={handleReset} />
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      {/* Hero */}
      <div>
        <h1
          style={{
            fontSize: "1.8rem",
            fontWeight: 700,
            marginBottom: 8,
            lineHeight: 1.3,
          }}
        >
          Detect Suspicious e-Challan Communications
        </h1>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.95rem", maxWidth: 680 }}>
          CivicShield analyses URLs, SMS messages, images, and PDF documents for
          signs of e-Challan and RTO fraud. Results are evidence-based — every
          finding is explained in plain language.
        </p>
      </div>

      {/* Disclaimer — always visible */}
      <LimitationDisclaimer />

      {/* Main two-column layout */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 340px",
          gap: 20,
          alignItems: "start",
        }}
      >
        {/* Left: input panel */}
        <div className="card">
          <div className="card-title">Submit for Analysis</div>
          {error && (
            <div
              id="error-banner"
              style={{
                background: "var(--risk-high-bg)",
                border: "1px solid var(--risk-high-border)",
                borderRadius: 8,
                padding: "10px 14px",
                marginBottom: 16,
                fontSize: "0.85rem",
                color: "#fca5a5",
              }}
            >
              ⚠️ {error}
            </div>
          )}
          <InputPanel
            onSubmitText={handleSubmitText}
            onSubmitFile={handleSubmitFile}
            loading={loading}
          />
        </div>

        {/* Right: demo selector */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <DemoSelector onSelect={handleDemo} />

          {/* How it works */}
          <div className="card card-sm">
            <div className="card-title">How It Works</div>
            <ol
              style={{
                display: "flex",
                flexDirection: "column",
                gap: 6,
                paddingLeft: 18,
              }}
            >
              {[
                "Submit URL, message, image or PDF",
                "Text extracted (OCR for images)",
                "URLs found and analysed structurally",
                "e-Challan and scam rules applied",
                "Evidence assembled, verdict computed",
                "Every signal explained in plain language",
              ].map((step, i) => (
                <li
                  key={i}
                  style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}
                >
                  {step}
                </li>
              ))}
            </ol>
          </div>

          {/* Official link */}
          <div className="official-link-card" style={{ padding: "10px 12px" }}>
            <span style={{ fontSize: "1rem" }}>🏛️</span>
            <div style={{ fontSize: "0.78rem", color: "var(--text-secondary)" }}>
              Official e-Challan portal:{" "}
              <a
                href="https://echallan.parivahan.gov.in/"
                target="_blank"
                rel="noopener noreferrer"
              >
                echallan.parivahan.gov.in
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* Loading overlay */}
      {loading && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(11,15,26,0.8)",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 200,
            gap: 16,
          }}
        >
          <div className="spinner" style={{ width: 36, height: 36, borderWidth: 3 }} />
          <div style={{ color: "var(--text-secondary)", fontSize: "0.9rem" }}>
            Analysing — please wait…
          </div>
        </div>
      )}
    </div>
  );
}
