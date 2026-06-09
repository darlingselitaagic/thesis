import axios from "axios"

const API_BASE_URL = "http://127.0.0.1:5000"

export const api = axios.create({
  baseURL: API_BASE_URL
})

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

export async function getXdrAlerts() {
  const res = await api.get<XdrAlert[]>("/api/xdr/wazuh-alerts")
  return res.data
}

export async function getXdrCorrelations() {
  const res = await api.get<XdrCorrelation[]>("/api/xdr/wazuh-correlations")
  return res.data
}

export async function getXdrResponses() {
  const res = await api.get<XdrResponse[]>("/api/xdr/wazuh-responses")
  return res.data
}

export async function getWazuhAgents() {
  const res = await api.get("/api/wazuh/agents")
  return res.data.data.affected_items as WazuhAgent[]
}

export async function getLogHistory() {
  const res = await api.get<XdrAlert[]>("/api/log-history")
  return res.data
}

export async function syncWazuhLogs() {
  const res = await api.get("/api/sync-wazuh-logs")
  return res.data
}