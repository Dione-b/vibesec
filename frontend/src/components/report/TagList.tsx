interface Props {
  items: string[];
}

export default function TagList({ items }: Props) {
  return (
    <div className="flex flex-wrap gap-2">
      {items.map((item, i) => (
        <span
          key={`${item}-${i}`}
          className="text-xs px-2 py-1 rounded-md bg-bg border border-border text-muted"
        >
          {item}
        </span>
      ))}
    </div>
  );
}
