// API helper for SecCopilot
// Handles requests to the Qoder Sites Function endpoint

export async function requestJson<T = unknown>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = new Error(`Request failed: ${response.status}`);
    throw error;
  }

  const data = await response.json();
  return data as T;
}
