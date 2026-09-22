import type { DemoCase } from "../types/analysis";
import { DEMO_CASES } from "../data/demoCases";

interface Props {
  onSelect: (demo: DemoCase) => void;
}

const demoIcons: Record<string, string> = {
  "demo-genuine": "✅",
  "demo-lookalike": "🎭",
  "demo-apk": "📲",
  "demo-urgent": "⚡",
  "demo-upi": "💳",
};

export function DemoSelector({ onSelect }: Props) {
  return (
    <div className="demo-selector">
      <div className="demo-title">Try a Demo Case</div>
      <div className="demo-list">
        {DEMO_CASES.map((demo) => (
          <button
            key={demo.id}
            className="demo-item"
            onClick={() => onSelect(demo)}
            title={demo.badge}
          >
            <span className="demo-item-icon">{demoIcons[demo.id] || "📋"}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="demo-item-label">{demo.label}</div>
              <div className="demo-item-desc">{demo.description}</div>
            </div>
            <span className="demo-badge">SYNTHETIC</span>
          </button>
        ))}
      </div>
    </div>
  );
}
