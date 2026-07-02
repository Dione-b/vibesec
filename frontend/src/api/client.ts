import type { Scan, Schedule } from "../types";

const BASE = "/api/v1";

function headers(): Record<string, string> {
  return { "Content-Type": "application/json" };
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${url}`, {
    ...init,
    headers: { ...headers(), ...init?.headers },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.error ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export async function healthCheck(): Promise<{ status: string; time: string }> {
  return request("/health");
}

export async function listScans(limit = 50): Promise<{ scans: Scan[] }> {
  return request(`/scans?limit=${limit}`);
}

export async function getScan(id: string): Promise<Scan> {
  return request(`/scans/${id}`);
}

export async function createScan(target: string): Promise<Scan> {
  return request("/scans", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
}

export async function listSchedules(): Promise<{ schedules: Schedule[] }> {
  return request("/schedules");
}

export async function createSchedule(
  target: string,
  intervalMinutes: number
): Promise<Schedule> {
  return request("/schedules", {
    method: "POST",
    body: JSON.stringify({ target, interval_minutes: intervalMinutes }),
  });
}
