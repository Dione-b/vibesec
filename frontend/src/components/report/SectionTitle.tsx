import type { ReactNode } from "react";

interface Props {
  children: ReactNode;
  className?: string;
}

export default function SectionTitle({ children, className = "" }: Props) {
  return (
    <h2 className={`text-xl font-bold border-b border-border pb-2 mb-4 ${className}`}>
      {children}
    </h2>
  );
}
