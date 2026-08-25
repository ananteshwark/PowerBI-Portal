/** @type {import('next').NextConfig} */
const API_ORIGIN = process.env.NEXT_PUBLIC_API_ORIGIN ?? 'http://localhost:4000';

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,

  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              // The Power BI SDK is loaded from our bundle, but the embedded
              // report runs in an iframe served by Microsoft.
              "frame-src https://app.powerbi.com https://*.powerbi.com",
              "child-src https://app.powerbi.com https://*.powerbi.com",
              // The iframe itself calls back to Power BI; our page calls our API.
              `connect-src 'self' ${API_ORIGIN} https://*.powerbi.com https://*.analysis.windows.net`,
              "img-src 'self' data: blob: https://*.powerbi.com",
              // Next.js injects inline styles; the SDK needs inline style attrs.
              "style-src 'self' 'unsafe-inline'",
              "script-src 'self' 'unsafe-inline'" + (process.env.NODE_ENV === 'development' ? " 'unsafe-eval'" : ''),
              "font-src 'self' data:",
              "object-src 'none'",
              "base-uri 'self'",
              "form-action 'self'",
              "frame-ancestors 'none'",
            ].join('; '),
          },
        ],
      },
    ];
  },
};

export default nextConfig;
