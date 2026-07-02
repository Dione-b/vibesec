import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { createScan, getScan, scanEventsUrl } from "../api/client";
import type { Scan } from "../types";

const TERMINAL_STATUSES = new Set<Scan["status"]>(["completed", "failed"]);
const ACTIVE_STATUSES = new Set<Scan["status"]>(["pending", "running"]);

export function useScan(scanId: string | null) {
  const queryClient = useQueryClient();
  const [fallbackPolling, setFallbackPolling] = useState(false);

  const scan = useQuery<Scan>({
    queryKey: ["scan", scanId],
    queryFn: () => getScan(scanId!),
    enabled: !!scanId,
    refetchInterval: fallbackPolling ? 2000 : false,
  });

  useEffect(() => {
    setFallbackPolling(false);
  }, [scanId]);

  useEffect(() => {
    if (!scanId || scan.isLoading || !scan.data) return;
    if (!ACTIVE_STATUSES.has(scan.data.status)) return;

    const es = new EventSource(scanEventsUrl(scanId));

    es.addEventListener("scan", (event) => {
      const updated = JSON.parse(event.data) as Scan;
      queryClient.setQueryData(["scan", scanId], updated);
      if (TERMINAL_STATUSES.has(updated.status)) {
        es.close();
      }
    });

    es.onerror = () => {
      es.close();
      setFallbackPolling(true);
    };

    return () => {
      es.close();
    };
  }, [scanId, scan.isLoading, scan.data?.status, queryClient]);

  return {
    scan: scan.data ?? null,
    isLoading: scan.isLoading,
    error: scan.error,
  };
}

export function useNewScan() {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: createScan,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}
