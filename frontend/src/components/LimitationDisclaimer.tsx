export function LimitationDisclaimer() {
  return (
    <div className="disclaimer-bar" role="note" aria-label="Limitation disclaimer">
      <span>🔒</span>
      <span>
        <strong>Limitation: </strong>
        CivicShield provides an evidence-based assessment and does not certify the
        authenticity of a government communication. Always verify challans independently
        at{" "}
        <a
          href="https://echallan.parivahan.gov.in/"
          target="_blank"
          rel="noopener noreferrer"
        >
          echallan.parivahan.gov.in
        </a>
        .
      </span>
    </div>
  );
}
