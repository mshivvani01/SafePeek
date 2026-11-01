import { useEffect, useState } from 'react';
import { useLive } from '../../hooks';
import { protectionService } from '../../services/protectionService';
export type PageId = 'dashboard' | 'files' | 'alerts' | 'activity' | 'history' | 'quarantine' | 'settings';
const items: { id: PageId; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' }, { id: 'files', label: 'Files' }, { id: 'alerts', label: 'Alerts' }, { id: 'activity', label: 'Activity' }, { id: 'history', label: 'Threat history' },
  { id: 'quarantine', label: 'Quarantine' }, { id: 'settings', label: 'Settings' }
];

export default function Sidebar({ page, onNavigate }: { page: PageId; onNavigate: (p: PageId) => void }) {
  const ps = useLive(protectionService.status, null);
  const [version, setVersion] = useState('');
  useEffect(() => { window.safepeek?.getAppInfo?.().then((i) => setVersion((i as { version?: string })?.version ?? '')).catch(() => undefined); }, []);
  return (
    <nav className="sidebar" aria-label="Main">
      <div className="brand"><span className="logo" aria-hidden>◉</span><div><strong>SafePeek</strong><small>Know what's inside before you open it.</small></div></div>
      <ul>
        {items.map((i) => (
          <li key={i.id}><button className={page === i.id ? 'nav active' : 'nav'} aria-current={page === i.id ? 'page' : undefined} onClick={() => onNavigate(i.id)}>{i.label}{i.id === 'alerts' && !!ps?.unreadAlerts && <span className="count">{ps.unreadAlerts}</span>}{i.id === 'quarantine' && !!ps?.quarantinedCount && <span className="count">{ps.quarantinedCount}</span>}</button></li>
        ))}
      </ul>
      <p className="version">{version ? `Version ${version}` : 'SafePeek'}</p>
    </nav>
  );
}
