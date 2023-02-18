/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  headers: [
    {
      key: 'Access-Control-Allow-Origin',
      value: '*',
    },
    {
      key: 'Cross-Origin-Embedder-Policy',
      value: 'require-corp',
    },
    {
      key: 'Cross-Origin-Opener-Policy',
      value: 'same-origin',
    },
  ],
};

module.exports = nextConfig;
