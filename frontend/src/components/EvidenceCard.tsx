import type { EvidenceItem as EvidenceItemType } from "../types/analysis";

interface Props {
  item: EvidenceItemType;
}

export function EvidenceCard({ item }: Props) {
  const isGenuine = item.evidence_type === "GENUINE_SIGNAL";
  const displaySeverity = isGenuine ? "INFO" : item.severity;

  const icons: Record<string, string> = {
    HIGH: "⚠️",
    MEDIUM: "🔶",
    LOW: "ℹ️",
    INFO: "✅",
  };

  return (
    <div className={`evidence-card ${displaySeverity}`}>
      <span className={`evidence-severity ${displaySeverity}`}>
        {displaySeverity}
      </span>
      <div className="evidence-content">
        <div className="evidence-finding">
          {icons[displaySeverity] || "•"} {item.finding}
        </div>
        <div className="evidence-explanation">{item.explanation}</div>
        <div className="evidence-source">
          source: {item.source}
          {item.rule_id ? ` · rule: ${item.rule_id}` : ""}
        </div>
      </div>
    </div>
  );
}
