import type { ScanDocument } from "../types";

function slugifyTarget(target: string): string {
  return target
    .replace(/^https?:\/\//i, "")
    .replace(/[^a-zA-Z0-9.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 60) || "report";
}

export function downloadTechnicalReportJSON(doc: ScanDocument, target: string): void {
  const date = new Date().toISOString().slice(0, 10);
  const filename = `vibesec-technical-${slugifyTarget(target)}-${date}.json`;
  const json = JSON.stringify(doc, null, 2);
  const blob = new Blob([json], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);

  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
