export default function StatCard({ label, value, tone, icon, hint }: { label: string; value: number; tone: string; icon?: string; hint?: string }) {
  return (
    <div className={`stat stat-${tone}`} title={hint}>
      <span className="stat-value">{value}</span>
      <span className="stat-label">{icon && <span aria-hidden="true">{icon} </span>}{label}</span>
    </div>
  );
}
