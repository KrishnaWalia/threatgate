import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const linkBase =
  'flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors';

export default function Sidebar() {
  const { user, isAdmin, logout } = useAuth();

  return (
    <aside className="w-56 shrink-0 border-r border-border bg-surface flex flex-col justify-between h-screen sticky top-0">
      <div>
        <div className="px-4 py-5 flex items-center gap-2 border-b border-border">
          <span className="h-2 w-2 rounded-full bg-safe" />
          <span className="font-mono text-sm tracking-wide">threatgate</span>
        </div>

        <nav className="p-3 space-y-1">
          <NavLink
            to="/dashboard"
            className={({ isActive }) =>
              `${linkBase} ${isActive ? 'bg-surface2 text-ink' : 'text-muted hover:text-ink hover:bg-surface2'}`
            }
          >
            Live Feed
          </NavLink>
          <NavLink
            to="/rules"
            className={({ isActive }) =>
              `${linkBase} ${isActive ? 'bg-surface2 text-ink' : 'text-muted hover:text-ink hover:bg-surface2'}`
            }
          >
            Detection Rules
          </NavLink>
          {isAdmin && (
            <NavLink
              to="/blocked-ips"
              className={({ isActive }) =>
                `${linkBase} ${isActive ? 'bg-surface2 text-ink' : 'text-muted hover:text-ink hover:bg-surface2'}`
              }
            >
              Blocked IPs
            </NavLink>
          )}
        </nav>
      </div>

      <div className="p-3 border-t border-border">
        <div className="px-3 py-2 mb-2">
          <p className="text-sm truncate">{user?.email}</p>
          <span
            className={`inline-block mt-1 text-[11px] font-mono uppercase tracking-wide px-1.5 py-0.5 rounded ${
              isAdmin ? 'bg-brand/15 text-brand' : 'bg-surface2 text-muted'
            }`}
          >
            {user?.role}
          </span>
        </div>
        <button
          onClick={logout}
          className="w-full text-left px-3 py-2 rounded-md text-sm text-muted hover:text-danger hover:bg-surface2 transition-colors"
        >
          Sign out
        </button>
      </div>
    </aside>
  );
}
