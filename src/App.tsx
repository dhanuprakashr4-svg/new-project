import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from '@/components/layout/AppShell';
import { Dashboard } from '@/pages/Dashboard';
import { DetectionLab } from '@/pages/DetectionLab';
import { DetectionAcademy } from '@/pages/DetectionAcademy';
import { AiAssistant } from '@/pages/AiAssistant';
import { Explainability } from '@/pages/Explainability';
import { MitreIntel } from '@/pages/MitreIntel';
import { SocCopilot } from '@/pages/SocCopilot';
import { ThreatDetection } from '@/pages/ThreatDetection';
import { EvidenceVault } from '@/pages/EvidenceVault';
import { VoxCrypt } from '@/pages/VoxCrypt';
import { Incidents } from '@/pages/Incidents';
import { IncidentDetail } from '@/pages/IncidentDetail';
import { AttackVisualization } from '@/pages/AttackVisualization';
import { Honeypot } from '@/pages/Honeypot';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<Dashboard />} />
          <Route path="threat-detection" element={<ThreatDetection />} />
          <Route path="attack-viz" element={<AttackVisualization />} />
          <Route path="honeypot" element={<Honeypot />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="incidents/:id" element={<IncidentDetail />} />
          <Route path="lab" element={<DetectionLab />} />
          <Route path="academy" element={<DetectionAcademy />} />
          <Route path="ai-assistant" element={<AiAssistant />} />
          <Route path="explainability" element={<Explainability />} />
          <Route path="mitre" element={<MitreIntel />} />
          <Route path="copilot" element={<SocCopilot />} />
          <Route path="evidence" element={<EvidenceVault />} />
          <Route path="voxcrypt" element={<VoxCrypt />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
