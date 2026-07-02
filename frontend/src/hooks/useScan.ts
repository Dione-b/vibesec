import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { createScan, getScan } from "../api/client";
import type { Scan } from "../types";

export function useScan(scanId: string | null) {
  const scan = useQuery<Scan>({
    queryKey: ["scan", scanId],
    queryFn: () => getScan(scanId!),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (status === "pending" || status === "running") return 2000;
      return false;
    },
  });

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
