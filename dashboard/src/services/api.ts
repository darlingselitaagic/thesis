import axios from "axios"
import type { XdrAlert, XdrCorrelation, XdrResponse, WazuhAgent } from "../types"

const API_BASE_URL = "http://127.0.0.1:5000"

export const api = axios.create({
  baseURL: API_BASE_URL
})

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