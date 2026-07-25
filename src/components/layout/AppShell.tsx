import { type ReactNode } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';

export function AppShell({ children }: { children?: ReactNode }) {
  return (
    <div className="flex min-h-screen text-soc-200">
      <Sidebar />
      <div className="flex-1 min-w-0 flex flex-col">
        <Topbar />
        <main className="flex-1 p-6 grid-bg">{children || <Outlet />}</main>
      </div>
    </div>
  );
}
