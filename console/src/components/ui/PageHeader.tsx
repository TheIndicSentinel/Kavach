import type { ReactNode } from "react";

type PageHeaderProps = {
  title: string;
  subtitle?: string;
  hindi?: string;
  action?: ReactNode;
};

export function PageHeader({ title, subtitle, hindi, action }: PageHeaderProps) {
  return (
    <header className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-kavach-900">
          {title}
        </h1>
        {hindi && (
          <p className="mt-0.5 text-sm font-medium text-peacock-600">{hindi}</p>
        )}
        {subtitle && (
          <p className="mt-2 max-w-2xl text-sm text-muted text-balance">
            {subtitle}
          </p>
        )}
      </div>
      {action}
    </header>
  );
}
