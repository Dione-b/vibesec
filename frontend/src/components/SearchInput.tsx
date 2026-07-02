interface SearchInputProps {
  onSubmit: (target: string) => void;
  disabled?: boolean;
}

export default function SearchInput({ onSubmit, disabled }: SearchInputProps) {
  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const input = e.currentTarget.elements.namedItem("target") as HTMLInputElement;
    const value = input.value.trim();
    if (value) onSubmit(value);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl">
      <div className="flex flex-col sm:relative gap-3 sm:gap-0 group">
        <input
          name="target"
          type="url"
          placeholder="https://example.com"
          disabled={disabled}
          required
          autoFocus
          className="w-full px-4 sm:px-6 py-3 sm:py-4 rounded-2xl bg-panel border border-border text-text placeholder:text-muted/50 text-base sm:text-lg focus:outline-none focus:border-accent/50 focus:ring-2 focus:ring-accent/20 transition-all disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={disabled}
          className="w-full sm:w-auto sm:absolute sm:right-3 sm:top-1/2 sm:-translate-y-1/2 px-5 py-2 rounded-xl bg-accent/10 border border-accent/30 text-accent font-medium hover:bg-accent/20 transition-colors disabled:opacity-50"
        >
          Escanear
        </button>
      </div>
    </form>
  );
}
