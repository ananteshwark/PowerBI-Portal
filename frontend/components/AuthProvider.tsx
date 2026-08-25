'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { useRouter } from 'next/navigation';
import {
  login as apiLogin,
  logout as apiLogout,
  restoreSession,
  setAccessToken,
  setUnauthenticatedHandler,
  type SessionUser,
} from '@/lib/api';

interface AuthState {
  user: SessionUser | null;
  /** True until the initial silent-restore attempt has settled. */
  initialising: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [initialising, setInitialising] = useState(true);
  const router = useRouter();

  /**
   * On mount, try to trade the HttpOnly refresh cookie for a new access token.
   * This is what makes a page refresh survive without keeping the access token
   * in localStorage, where any injected script could read it.
   */
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { accessToken, user: restored } = await restoreSession();
        if (cancelled) return;
        setAccessToken(accessToken);
        setUser(restored);
      } catch {
        // No valid cookie — anonymous. Not an error worth surfacing.
      } finally {
        if (!cancelled) setInitialising(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Lets the API client force a sign-out when a refresh ultimately fails.
  useEffect(() => {
    setUnauthenticatedHandler(() => {
      setUser(null);
      setAccessToken(null);
      router.replace('/login');
    });
    return () => setUnauthenticatedHandler(null);
  }, [router]);

  const signIn = useCallback(async (email: string, password: string) => {
    const { accessToken, user: signedIn } = await apiLogin(email, password);
    setAccessToken(accessToken);
    setUser(signedIn);
  }, []);

  const signOut = useCallback(async () => {
    // Best-effort: even if the server call fails, drop local state.
    await apiLogout().catch(() => undefined);
    setAccessToken(null);
    setUser(null);
    router.replace('/login');
  }, [router]);

  const value = useMemo<AuthState>(
    () => ({ user, initialising, signIn, signOut }),
    [user, initialising, signIn, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within <AuthProvider>');
  return ctx;
}

/**
 * Client-side route guard.
 *
 * Convenience only — it hides UI, it does not protect data. Every protected
 * response comes from the backend, which re-checks the JWT and the report
 * grant on every request.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, initialising } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!initialising && !user) router.replace('/login');
  }, [initialising, user, router]);

  if (initialising) {
    return (
      <div className="page-state">
        <span className="spinner" aria-hidden="true" />
        <p>Restoring your session…</p>
      </div>
    );
  }
  if (!user) return null;
  return <>{children}</>;
}
