import { useState } from "react";
import { useNavigate } from "react-router";
import { useNewScan } from "../hooks/useScan";
import SearchInput from "../components/SearchInput";
import ScanSkeleton from "../components/ScanSkeleton";

export default function Home() {
  const [target, setTarget] = useState<string | null>(null);
  const navigate = useNavigate();
  const newScan = useNewScan();

  const handleSubmit = (t: string) => {
    setTarget(t);
    newScan.mutate(t, {
      onSuccess: (scan) => {
        navigate(`/reports/${scan.id}`);
      },
      onError: () => {
        setTarget(null);
      },
    });
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4 sm:px-6 relative">
      <div className="text-center mb-10">
        <h1 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-text">
          Vibe<span className="text-accent">Sec</span>
        </h1>
        <p className="text-muted mt-3 text-base sm:text-lg">Security reconnaissance para aplicações web</p>
      </div>

      {target ? (
        <ScanSkeleton target={target} />
      ) : (
        <SearchInput onSubmit={handleSubmit} />
      )}

      {newScan.isError && (
        <div className="mt-6 max-w-md w-full px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm text-center">
          {(newScan.error as Error)?.message ?? "Erro ao criar scan"}
        </div>
      )}
    </div>
  );
}
