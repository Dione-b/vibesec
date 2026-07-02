import type { ReactNode } from "react";

interface Props {
  children: ReactNode;
  className?: string;
}

export default function ReportCard({ children, className = "" }: Props) {
  return (
    <div
      className={`bg-gradient-to-b from-panel to-panel-2 border border-border rounded-2xl p-4 sm:p-5 shadow-lg shadow-black/25 ${className}`}
    >
      {children}
    </div>
  );
}
