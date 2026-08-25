'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/components/AuthProvider';
import { ApiError } from '@/lib/api';

export default function LoginPage() {
  const { user, initialising, signIn } = useAuth();
  const router = useRouter();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Already signed in (e.g. arrived here by typing the URL) — move along.
  useEffect(() => {
    if (!initialising && user) router.replace('/dashboard');
  }, [initialising, user, router]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await signIn(email, password);
      router.replace('/dashboard');
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 429
          ? err.message
          : err instanceof ApiError && err.status === 401
            ? 'Invalid email or password.'
            : 'Sign-in failed. Please try again.',
      );
      setSubmitting(false);
    }
  }

  return (
    <main className="auth">
      <form className="auth__card" onSubmit={handleSubmit}>
        <span className="header__mark header__mark--lg" aria-hidden="true" />
        <h1 className="auth__title">Analytics Portal</h1>
        <p className="auth__subtitle">Sign in to view your dashboards.</p>

        {error && (
          <p className="alert alert--error" role="alert">
            {error}
          </p>
        )}

        <label className="field">
          <span className="field__label">Email</span>
          <input
            className="field__input"
            type="email"
            name="email"
            autoComplete="username"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={submitting}
          />
        </label>

        <label className="field">
          <span className="field__label">Password</span>
          <input
            className="field__input"
            type="password"
            name="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={submitting}
          />
        </label>

        <button type="submit" className="btn btn--primary btn--block" disabled={submitting}>
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>

        <p className="auth__note">
          No Power BI licence is required. Your access is determined by your portal role.
        </p>
      </form>
    </main>
  );
}
