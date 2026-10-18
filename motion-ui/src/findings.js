// Presentation grouping only: do not merge, delete or change stored evidence.
const headerChecks = new Set(['content-security-policy','x-content-type-options','x-frame-options','hsts']);
export function groupFindings(findings) {
  const groups = new Map();
  findings.forEach((finding, index) => {
    const key = headerChecks.has(finding.check)
      ? JSON.stringify([finding.check, finding.title, finding.severity, finding.verdict])
      : `finding-${index}`;
    if (!groups.has(key)) groups.set(key, {key, findings: []});
    groups.get(key).findings.push(finding);
  });
  return [...groups.values()];
}
