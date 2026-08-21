'use client';

import { use, useEffect, useState } from 'react';
import Link from 'next/link';
import { RequireAuth } from '@/components/AuthProvider';
import PortalHeader from '@/components/PortalHeader';
import PowerBIReport from '@/components/PowerBIReport';
import { fetchReport, type ReportSummary } from '@/lib/api';

export default function ReportPage({ params }: { params: Promise<{ slug: string }> }) {
  // Next.js 15: route params are a promise.
  const { slug } = use(params);
  const [meta, setMeta] = useState<ReportSummary | null>(null);

  // Title/description only. The embed component fetches the token itself, and
  // the backend re-authorizes there regardless of what we render here.
  useEffect(() => {
    let cancelled = false;
    fetchReport(slug)
      .then((report) => {
        if (!cancelled) setMeta(report);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [slug]);

  return (
    <RequireAuth>
      <PortalHeader />
      <main className="main main--report">
        <nav className="breadcrumb">
          <Link href="/dashboard">Dashboards</Link>
          <span aria-hidden="true">/</span>
          <span>{meta?.name ?? 'Report'}</span>
        </nav>

        {meta && (
          <div className="main__intro">
            <h1 className="main__title">{meta.name}</h1>
            {meta.description && <p className="main__subtitle">{meta.description}</p>}
          </div>
        )}

        <PowerBIReport slug={slug} />
      </main>
    </RequireAuth>
  );
}
