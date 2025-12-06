import { useState, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { ChevronDown, ChevronRight } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

interface SubItem {
  href: string;
  label: string;
}

interface NavItem {
  href?: string;
  icon: LucideIcon;
  label: string;
  subItems?: SubItem[];
}

export const CollapsibleNav = ({ item }: { item: NavItem }) => {
  const location = useLocation();
  const isSubItemActive = item.subItems?.some(subItem => location.pathname.startsWith(subItem.href)) ?? false;
  const [isOpen, setIsOpen] = useState(isSubItemActive);

  useEffect(() => {
    if (isSubItemActive) {
      setIsOpen(true);
    }
  }, [isSubItemActive, location.pathname]);

  if (item.subItems) {
    return (
      <div>
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center justify-between w-full px-3 py-2 text-sm font-medium rounded-md text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800"
        >
          <div className="flex items-center">
            <item.icon className="w-5 h-5 mr-3" />
            <span>{item.label}</span>
          </div>
          {isOpen ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
        </button>
        {isOpen && (
          <div className="pl-8 space-y-1 py-1">
            {item.subItems.map((subItem) => (
              <NavLink
                key={subItem.label}
                to={subItem.href}
                className={({ isActive }) =>
                  `flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                    isActive
                      ? 'bg-primary text-primary-foreground'
                      : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800'
                  }`
                }
              >
                <span>{subItem.label}</span>
              </NavLink>
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <NavLink
      to={item.href!}
      className={({ isActive }) =>
        `flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
          isActive
            ? 'bg-primary text-primary-foreground'
            : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800'
        }`
      }
    >
      <item.icon className="w-5 h-5 mr-3" />
      <span>{item.label}</span>
    </NavLink>
  );
};
