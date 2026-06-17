
export const useAnalysis = () => {
 function getRiskLabel(score: number) {
  if (score >= 85) return "Critical"
  if (score >= 60) return "High"
  if (score >= 30) return "Medium"
  return "Low"
}
    return {getRiskLabel}
}