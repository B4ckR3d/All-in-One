import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'All-in-One Security Toolkit',
  description: 'Recon • Scanner • CVE • Lookup',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
