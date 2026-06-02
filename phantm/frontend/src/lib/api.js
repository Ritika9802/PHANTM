import axios from "axios";

const api = axios.create({ baseURL: "/api" });

export const scanAPI = {
  create: (target, scanType, apiKey) => api.post("/scan", { target, scanType, apiKey }),
  get: (id) => api.get(`/scan/${id}`),
  list: () => api.get("/scan/"),
  logs: (id) => api.get(`/scan/${id}/logs`),
  delete: (id) => api.delete(`/scan/${id}`),
};

export const intelAPI = {
  chat: (messages, scanContext, apiKey) => api.post("/intel/chat", { messages, scanContext, apiKey }),
  cve: (id) => api.get(`/intel/cve/${id}`),
  report: (scanId, format, apiKey) => api.post("/intel/report", { scanId, format, apiKey }),
};

export const reportsAPI = {
  list: () => api.get("/reports/"),
  findings: (scanId) => api.get(`/reports/${scanId}/findings`),
};

export const hunterAPI = {
  run: (targets, vulnType, apiKey) => api.post("/hunter/", { targets, vulnType, apiKey }),
};

export function createWS(scanId) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.host;
  return new WebSocket(`${protocol}//${host}/api?scanId=${scanId}`);
}

// Direct WS connection to backend
export function createScanWS(scanId) {
  return new WebSocket(`ws://localhost:3001?scanId=${scanId}`);
}
