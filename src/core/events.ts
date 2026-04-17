// Shared event bus — SSE subscribers for dashboard
// Separated from monitor entry point so dashboard can import without triggering monitor startup

export type EventHandler = (event: string, data: any) => void;

export const sseSubscribers = new Set<EventHandler>();

export function broadcast(event: string, data: any): void {
  for (const sub of sseSubscribers) {
    try { sub(event, data); } catch { /* */ }
  }
}
