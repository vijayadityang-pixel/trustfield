// Backend risk_score is always a float in [0.0, 1.0] (see backend/detection/risk_scorer.py).
// UI components display it as a 0-100 percent. Convert at the boundary, once, here -
// never format `risk_score` directly in a component.

/**
 * Convert a raw 0.0-1.0 risk_score into a rounded 0-100 percent for display.
 * Tolerant of already-scaled values (>1) in case a caller passes a percent by mistake.
 */
export function riskPercent(score) {
  if (score == null || Number.isNaN(score)) return 0
  const normalized = score > 1 ? score : score * 100
  return Math.round(Math.min(100, Math.max(0, normalized)))
}

/**
 * Bucket a raw 0.0-1.0 risk_score into a severity class.
 * Thresholds are on the 0-100 scale to match backend severity cuts
 * (alert_generator.py: 0.85 critical / 0.7 high / 0.55 medium).
 */
export function riskBucket(score) {
  const pct = riskPercent(score)
  if (pct >= 85) return 'critical'
  if (pct >= 70) return 'high'
  if (pct >= 55) return 'medium'
  return 'low'
}

/**
 * CSS var name for a raw 0.0-1.0 risk_score, ready to drop into `var(...)`.
 */
export function riskColor(score) {
  return `var(--risk-${riskBucket(score)})`
}
