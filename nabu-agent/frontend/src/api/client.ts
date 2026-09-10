// Typed REST client. Every error comes back as the platform error envelope
// { code, message, request_id, details } (see backend routers). Full typing lands in Phase 2.
export interface ApiError {
  code: string;
  message: string;
  request_id: string;
  details: Record<string, unknown>;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as Partial<ApiError>;
    throw new Error(err.message ?? `HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}
