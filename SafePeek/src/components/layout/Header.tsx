import { monitoringService } from '../../services/monitoringService';
import { useLive } from '../../hooks';

export default function Header({ title }: { title: string }) {
  const st = useLive(monitoringService.status, null);
  const demo = !monitoringService.available();
  const label = demo ? 'Preview (no agent)' : st?.active ? 'Monitoring Active' : st && !st.enabled ? 'Monitoring Paused' : 'Monitoring Inactive';
  const tone = st?.active ? 'ok' : 'off';
  return (
    <header className="topbar">
      <h1>{title}</h1>
      <div className={`status-pill ${tone}`} title="New files are analyzed locally: static analysis, content analysis, then heuristic threat assessment.">
        <i className="dot" /> {st?.active ? 'Protection Active · ' : ''}{label}
      </div>
    </header>
  );
}
