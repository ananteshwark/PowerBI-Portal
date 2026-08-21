'use client';

import Link from 'next/link';
import { useAuth } from './AuthProvider';

export default function PortalHeader() {
  const { user, signOut } = useAuth();

  const initials = (user?.displayName ?? '')
    .split(' ')
    .map((part) => part[0])
    .filter(Boolean)
    .slice(0, 2)
    .join('')
    .toUpperCase();

  return (
    <header className="header">
      <Link href="/dashboard" className="header__brand">
        <span className="header__mark" aria-hidden="true" />
        <span>Analytics Portal</span>
      </Link>

      {user && (
        <div className="header__user">
          <div className="header__user-meta">
            <span className="header__user-name">{user.displayName}</span>
            <span className="header__user-roles">
              {user.roles.length ? user.roles.join(' · ') : 'No roles assigned'}
            </span>
          </div>
          <span className="avatar" aria-hidden="true">{initials || '?'}</span>
          <button type="button" className="btn btn--ghost" onClick={() => void signOut()}>
            Sign out
          </button>
        </div>
      )}
    </header>
  );
}
