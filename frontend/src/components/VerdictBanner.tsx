import type { AnalysisResult } from "../types/analysis";

interface Props {
  result: AnalysisResult;
}

export function VerdictBanner({ result }: Props) {
  const icons: Record<string, string> = {
    "Likely Fraudulent": "🛡️",
    "Likely Genuine": "✅",
    "Unable to Verify": "⚠️",
  };

  const riskClass = result.risk_level;

  return (
    <div className={`verdict-banner ${riskClass}`}>
      <div className="verdict-icon">{icons[result.verdict]}</div>
      <div className="verdict-text">
        <h1 className={riskClass}>{result.verdict}</h1>
        <p className="verdict-reasoning">{result.verdict_reasoning}</p>
        <div className="verdict-counts">
          {result.high_severity_count > 0 && (
            <span className="count-chip high">
              {result.high_severity_count} HIGH signal{result.high_severity_count !== 1 ? "s" : ""}
            </span>
          )}
          {result.medium_severity_count > 0 && (
            <span className="count-chip medium">
              {result.medium_severity_count} MEDIUM signal{result.medium_severity_count !== 1 ? "s" : ""}
            </span>
          )}
          {result.low_severity_count > 0 && (
            <span className="count-chip low">
              {result.low_severity_count} LOW signal{result.low_severity_count !== 1 ? "s" : ""}
            </span>
          )}
          {result.high_severity_count === 0 &&
            result.medium_severity_count === 0 &&
            result.low_severity_count === 0 && (
              <span className="count-chip low">No significant suspicious signals</span>
            )}
        </div>
      </div>
    </div>
  );
}
