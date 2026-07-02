export default function ScanSkeleton({ target }: { target: string }) {
  return (
    <div className="w-full max-w-2xl mx-auto animate-pulse">
      <div className="text-center mb-8">
        <div className="inline-flex items-center gap-3 px-4 py-2 rounded-full bg-panel border border-border">
          <span className="relative flex h-3 w-3">
            <span className="absolute inline-flex h-full w-full rounded-full bg-accent opacity-75 animate-ping" />
            <span className="relative inline-flex h-3 w-3 rounded-full bg-accent" />
          </span>
          <span className="text-muted text-sm">Escaneando</span>
        </div>
        <p className="text-text font-medium mt-4 text-lg">{target}</p>
      </div>

      <div className="space-y-3">
        <div className="h-20 rounded-xl bg-panel border border-border" />
        <div className="h-20 rounded-xl bg-panel border border-border" />
        <div className="h-20 rounded-xl bg-panel border border-border" />
        <div className="h-14 rounded-xl bg-panel border border-border w-3/4 mx-auto" />
      </div>
    </div>
  );
}
