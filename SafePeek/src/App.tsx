import { useEffect, useState } from 'react';
import Sidebar, { PageId } from './components/layout/Sidebar';
import Header from './components/layout/Header';
import Dashboard from './pages/Dashboard';
import Files from './pages/Files';
import Alerts from './pages/Alerts';
import Activity from './pages/Activity';
import ThreatHistory from './pages/ThreatHistory';
import Quarantine from './pages/Quarantine';
import Settings from './pages/Settings';
import { protectionService } from './services/protectionService';

const titles: Record<PageId, string> = { dashboard: 'Dashboard', files: 'Files', alerts: 'Security Alerts', activity: 'Activity', history: 'Threat History', quarantine: 'Quarantine', settings: 'Settings' };
const PAGES: PageId[] = ['dashboard', 'files', 'alerts', 'activity', 'history', 'quarantine', 'settings'];

export default function App() {
  const [page, setPage] = useState<PageId>('dashboard');
  const [fileId, setFileId] = useState<string | null>(null);
  const open = (id: string, alertId?: string) => { setFileId(id); setPage('files'); if (alertId) protectionService.markRead(alertId); };
  // Clicking a desktop notification brings the app forward and lands on that file's detail screen (the file itself is never opened).
  useEffect(() => window.safepeek?.onNavigate?.((t) => { if (t.fileId) open(t.fileId, t.alertId); else if (PAGES.includes(t.page as PageId)) setPage(t.page as PageId); }), []);
  return (
    <div className="shell">
      <Sidebar page={page} onNavigate={(p) => setPage(p)} />
      <main className="main">
        <Header title={titles[page]} />
        <div className="content">
          {page === 'dashboard' && <Dashboard onOpenFile={(id) => open(id)} onNavigate={(p) => setPage(p)} />}{page === 'files' && <Files selectedId={fileId} />}{page === 'alerts' && <Alerts onOpenFile={open} />}{page === 'activity' && <Activity />}
          {page === 'history' && <ThreatHistory onOpenFile={open} />}{page === 'quarantine' && <Quarantine onOpenFile={(id) => open(id)} />}{page === 'settings' && <Settings />}
        </div>
      </main>
    </div>
  );
}
