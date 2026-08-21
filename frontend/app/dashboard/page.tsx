'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { RequireAuth, useAuth } from '@/components/AuthProvider';
import PortalHeader from '@/components/PortalHeader';
import { fetchReports, type ReportSummary } from '@/lib/api';

function ReportGrid() {
  const { user } = useAuth();
  const [reports, setReports] = useState<ReportSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchReports()
      .then(({ reports: list }) => !cancelled && setReports(list))
      .catch(() => !cancelled && setError('Could not load your reports.'));
    return () => {
      cancelled = true;
    };
  }, []);

  // Group by category so a long catalogue stays navigable.
  const grouped = useMemo(() => {
    if (!reports) return [];
    const map = new Map<string, ReportSummary[]>();
    for (const report of reports) {
      const key = report.category ?? 'Other';
      map.set(key, [...(map.get(key) ?? []), report]);
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [reports]);

  if (error) {
    return (
      <p className="alert alert--error" role="alert">
        {error}
      </p>
    );
  }

  if (!reports) {
    return (
      <div className="page-state">
        <span className="spinner" aria-hidden="true" />
        <p>Loading your reports…</p>
      </div>
    );
  }

  if (reports.length === 0) {
    return (
      <div className="empty">
        <h2>No reports available</h2>
        <p>
          Your account has no dashboards assigned yet. Ask an administrator to grant access to
          your role{user?.roles.length ? ` (${user.roles.join(', ')})` : ''}.
        </p>
      </div>
    );
  }

  return (
    <>
      {grouped.map(([category, items]) => (
        <section key={category} className="section">
          <h2 className="section__title">{category}</h2>
          <ul className="grid">
            {items.map((report) => (
              <li key={report.id}>
                <Link href={`/reports/${report.slug}`} className="card">
                  <h3 className="card__title">{report.name}</h3>
                  {report.description && <p className="card__desc">{report.description}</p>}
                  <span className="card__footer">
                    {report.rlsEnabled && (
                      <span className="badge" title="Row-level security is applied to this report">
                        RLS
                      </span>
                    )}
                    <span className="card__cta">Open →</span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </>
  );
}

export default function DashboardPage() {
  const { user } = useAuth();

  return (
    <RequireAuth>
      <PortalHeader />
      <main className="main">
        <div className="main__intro">
          <h1 className="main__title">
            {user ? `Welcome back, ${user.displayName.split(' ')[0]}` : 'Your dashboards'}
          </h1>
          <p className="main__subtitle">
            Reports are filtered to the data your role permits.
          </p>
        </div>
        <ReportGrid />
      </main>
    </RequireAuth>
  );
}
