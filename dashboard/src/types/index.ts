import type { ReactNode } from "react"
import type { PageName } from "../App"

export type MetricCardsProps = {
  title: string
  value: string | number
  label: string
  icon: ReactNode
  danger?: boolean
}

export type HeaderProps = {
  title: string
  subtitle: string
}

export type SideNavProps = {
  activePage: PageName
  onNavigate: (page: PageName) => void
}

export type StatsCardProps = {
  title: string
  value: number | string
  icon?: ReactNode
}

export type StatusProps = {
  title: string
  status: "Running" | "Connected" | "Disconnected" | "Stopped"
  description: string
}

export type XdrAlert = {
  id: number
  timestamp: string
  endpoint: string
  event_type: string
  severity: string
  source_ip: string
  description: string
  threat_score: number
  classification: string
  recommended_action: string
  is_anomaly: boolean
  anomaly_score: number
}

export type XdrCorrelation = {
  endpoint: string
  correlation_score: number
  detected_patterns: string[]
  related_events: number[]
  recommended_action: string
  attack_chain: string[]
  possible_attack_stage: string
  related_event_count: number
  mitre_mapping: {
    technique_id: string
    technique: string
  }[]
}

export type XdrResponse = {
  endpoint: string
  action: string
  status: string
  timestamp: string
  correlation_score: number
  detected_patterns: string[]
  related_events: number[]
  risk_level: string
  confidence: string
  explanation?: {
    action: string
    endpoint: string
    risk_level: string
    confidence: string
    why_this_action: string
    possible_attack_stage: string
    mitre_mapping: {
      technique_id: string
      technique: string
    }[]
    evidence: string[]
    related_events: number[]
    recommended_next_steps: string[]
  }
}

export type WazuhAgent = {
  id: string
  name: string
  ip: string
  status: string
  os?: {
    name: string
    platform: string
    version: string
  }
}