import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import AuditPage from "./pages/AuditPage";
import BatchJobDetailPage from "./pages/BatchJobDetailPage";
import BatchJobsPage from "./pages/BatchJobsPage";
import EvaluatePage from "./pages/EvaluatePage";
import FairnessPage from "./pages/FairnessPage";
import IncidentsPage from "./pages/IncidentsPage";
import ModelDetailPage from "./pages/ModelDetailPage";
import ModelsPage from "./pages/ModelsPage";
import OverviewPage from "./pages/OverviewPage";
import PoliciesPage from "./pages/PoliciesPage";
import PolicyDetailPage from "./pages/PolicyDetailPage";
import RetentionPage from "./pages/RetentionPage";
import SettingsPage from "./pages/SettingsPage";

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/overview" replace />} />
        <Route path="overview" element={<OverviewPage />} />
        <Route path="evaluate" element={<EvaluatePage />} />
        <Route path="policies" element={<PoliciesPage />} />
        <Route path="policies/:packId" element={<PolicyDetailPage />} />
        <Route path="models" element={<ModelsPage />} />
        <Route path="models/:modelId" element={<ModelDetailPage />} />
        <Route path="batch" element={<BatchJobsPage />} />
        <Route path="batch/:jobId" element={<BatchJobDetailPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="fairness" element={<FairnessPage />} />
        <Route path="retention" element={<RetentionPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Route>
    </Routes>
  );
}
