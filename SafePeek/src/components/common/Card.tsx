import type { ReactNode } from 'react';

export default function Card({ title, children, aside }: { title?: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="card">
      {(title || aside) && <header className="card-head"><h2>{title}</h2>{aside}</header>}
      {children}
    </section>
  );
}
