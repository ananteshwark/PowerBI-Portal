/** Shapes shared between services, routes and (via the frontend copy) the UI. */

export interface UserRecord {
  id: string;
  email: string;
  displayName: string;
  department: string | null;
  /** What we assert to Power BI as identities[].username. */
  effectiveUsername: string;
  isActive: boolean;
}

export interface AuthenticatedUser extends UserRecord {
  /** Portal role names, e.g. ['sales_manager']. */
  roles: string[];
  isAdmin: boolean;
}

/** Row from the user_report_access view. */
export interface AccessibleReport {
  reportId: string;
  slug: string;
  name: string;
  description: string | null;
  category: string | null;
  workspaceId: string;
  pbiReportId: string;
  pbiDatasetId: string | null;
  rlsRequired: boolean;
  tokenLifetimeMinutes: number;
}

/** The effective identity handed to Power BI's GenerateToken. */
export interface EffectiveIdentity {
  username: string;
  roles: string[];
  datasets: string[];
  /** Extra key/values from user_rls_attributes, surfaced for audit/debug. */
  attributes: Record<string, string>;
}

export interface EmbedConfigResponse {
  reportId: string;
  embedUrl: string;
  embedToken: string;
  /** ISO-8601. The client refreshes before this. */
  expiresAt: string;
  tokenType: 'Embed';
  /** Echoed back so the UI can show "viewing as ..." — never trusted as input. */
  rls: { username: string; roles: string[] } | null;
}
