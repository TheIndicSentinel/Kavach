import { useEffect } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { SessionGate } from "./components/layout/SessionGate";
import AgentDetailPage from "./pages/AgentDetailPage";
import AgentEvidencePage from "./pages/AgentEvidencePage";
import AgentsPage from "./pages/AgentsPage";
import AuditPage from "./pages/AuditPage";
import BatchJobDetailPage from "./pages/BatchJobDetailPage";
import BatchJobsPage from "./pages/BatchJobsPage";
import ChangeRequestsPage from "./pages/ChangeRequestsPage";
import DecisionEventsPage from "./pages/DecisionEventsPage";
import EvaluatePage from "./pages/EvaluatePage";
import IncidentsPage from "./pages/IncidentsPage";
import ModelDetailPage from "./pages/ModelDetailPage";
import ModelsPage from "./pages/ModelsPage";
import OverviewPage from "./pages/OverviewPage";
import PoliciesPage from "./pages/PoliciesPage";
import PolicyDetailPage from "./pages/PolicyDetailPage";
import ReconciliationPage from "./pages/ReconciliationPage";
import RetentionPage from "./pages/RetentionPage";
import SettingsPage from "./pages/SettingsPage";
import SignInPage from "./pages/SignInPage";
import { startSession } from "./lib/session";

export default function App() {
  // Once per page load: GET /auth/config decides the mode, then (login mode)
  // GET /auth/session. No page renders until both are known.
  useEffect(() => {
    void startSession();
  }, []);

  return (
    <Routes>
      <Route path="signin" element={<SignInPage />} />
      <Route element={<SessionGate />}>
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="overview" element={<OverviewPage />} />
          <Route path="evaluate" element={<EvaluatePage />} />
          <Route path="agents" element={<AgentsPage />} />
          <Route path="agents/:agentId" element={<AgentDetailPage />} />
          <Route path="agent-evidence" element={<AgentEvidencePage />} />
          <Route path="reconciliation" element={<ReconciliationPage />} />
          <Route path="decision-events" element={<DecisionEventsPage />} />
          <Route path="policies" element={<PoliciesPage />} />
          <Route path="policies/:packId" element={<PolicyDetailPage />} />
          <Route path="models" element={<ModelsPage />} />
          <Route path="models/:modelId" element={<ModelDetailPage />} />
          <Route path="batch" element={<BatchJobsPage />} />
          <Route path="batch/:jobId" element={<BatchJobDetailPage />} />
          <Route path="changes" element={<ChangeRequestsPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="incidents" element={<IncidentsPage />} />
          <Route path="retention" element={<RetentionPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}
