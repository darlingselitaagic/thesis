import { useState } from "react"
import { syncWazuhLogs, getLogHistory, getXdrResponses, getWazuhAgents } from "../services/api"
import type { XdrAlert, XdrResponse, WazuhAgent } from "../types"

export const useOverview = () => {

      const [alerts, setAlerts] = useState<XdrAlert[]>([])
      const [responses, setResponses] = useState<XdrResponse[]>([])
      const [agents, setAgents] = useState<WazuhAgent[]>([])

    const refreshLogsOverview = () =>{
         syncWazuhLogs().then(() => {
        Promise.all([getLogHistory(), getXdrResponses(), getWazuhAgents()])
          .then(([alertsData, responsesData, agentsData]) => {
            setAlerts(alertsData)
            setResponses(responsesData)
            setAgents(agentsData)
          })
      })
    }

      const critical = alerts.filter(a => a.classification === "Critical").length
      const activeAgents = agents.filter(a => a.status === "active").length
      const recentAlerts = alerts.slice(0, 6)
      const recentResponses = responses.slice(0, 4)
     

      return {alerts, responses, agents, setAlerts, setResponses, setAgents, refreshLogsOverview, critical, activeAgents, recentAlerts, recentResponses}
}