/** In-app notification bus (toasts shown inside the window). Native Windows notifications are sent by the main process. */
type Listener = (msg: string) => void;
const listeners = new Set<Listener>();
export const notificationService = {
  subscribe(l: Listener) { listeners.add(l); return () => { listeners.delete(l); }; },
  notify(msg: string) { listeners.forEach((l) => l(msg)); }
};
