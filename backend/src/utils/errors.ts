/**
 * Errors that are safe to surface to a client carry an explicit status and
 * code. Everything else becomes a generic 500 in the error handler — we never
 * leak Power BI/Entra internals (which routinely include tenant identifiers and
 * request correlation data) to the browser.
 */
export class AppError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;
  /** Attached to logs but never sent to the client. */
  readonly internal?: unknown;

  constructor(
    status: number,
    code: string,
    message: string,
    opts: { details?: unknown; internal?: unknown; cause?: unknown } = {},
  ) {
    super(message, opts.cause ? { cause: opts.cause } : undefined);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    this.details = opts.details;
    this.internal = opts.internal;
  }
}

export const badRequest = (msg: string, details?: unknown) =>
  new AppError(400, 'bad_request', msg, { details });

export const unauthorized = (msg = 'Authentication required') =>
  new AppError(401, 'unauthorized', msg);

export const forbidden = (msg = 'You do not have access to this resource') =>
  new AppError(403, 'forbidden', msg);

export const notFound = (msg = 'Resource not found') =>
  new AppError(404, 'not_found', msg);

export const upstreamError = (msg: string, internal?: unknown) =>
  new AppError(502, 'upstream_error', msg, { internal });
