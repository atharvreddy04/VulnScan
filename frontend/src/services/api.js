const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

async function handleResponse(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data.detail || `Request failed with status ${response.status}`;
    throw new Error(message);
  }
  return data;
}

export const vulnScanApi = {
  async checkHealth() {
    const res = await fetch(`${API_BASE_URL}/api/health`);
    return handleResponse(res);
  },

  async startNetworkScan({ target, profile = "safe", explicitAuthorization = false }) {
    const res = await fetch(`${API_BASE_URL}/api/network/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        profile,
        explicit_authorization: explicitAuthorization,
      }),
    });
    return handleResponse(res);
  },

  async getNetworkScan(scanId) {
    const res = await fetch(`${API_BASE_URL}/api/network/scans/${scanId}`);
    return handleResponse(res);
  },

  async pollNetworkScan(scanId, { intervalMs = 2000, onUpdate, signal } = {}) {
    while (!signal?.aborted) {
      const scanData = await this.getNetworkScan(scanId);
      if (onUpdate) {
        onUpdate(scanData);
      }
      if (scanData.status === "completed" || scanData.status === "failed") {
        return scanData;
      }
      await new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, intervalMs);
        signal?.addEventListener(
          "abort",
          () => {
            clearTimeout(timer);
            reject(new DOMException("Polling aborted", "AbortError"));
          },
          { once: true }
        );
      });
    }
  },

  async getDashboardSummary() {
    const res = await fetch(`${API_BASE_URL}/api/dashboard/summary`);
    return handleResponse(res);
  },

  async runWebAudit({ targetUrl, explicitAuthorization = false }) {
    const res = await fetch(`${API_BASE_URL}/api/web/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: targetUrl,
        explicit_authorization: explicitAuthorization,
      }),
    });
    return handleResponse(res);
  },

  async runDnsRecon(domain) {
    const res = await fetch(
      `${API_BASE_URL}/api/recon/dns?domain=${encodeURIComponent(domain)}`
    );
    return handleResponse(res);
  },

  async listFindings() {
    const res = await fetch(`${API_BASE_URL}/api/vulnerabilities`);
    return handleResponse(res);
  },

  async listScans() {
    const res = await fetch(`${API_BASE_URL}/api/dashboard/scans`);
    return handleResponse(res);
  },
};