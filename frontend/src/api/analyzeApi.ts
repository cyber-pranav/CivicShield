/**
 * CivicShield — API Client
 * Typed fetch wrapper for the FastAPI backend.
 */

import type { AnalysisResult, AnalysisMode } from "../types/analysis";

function getApiBaseUrl(): string {
  // 1. Environment variable if provided at build time
  const envUrl = import.meta.env.VITE_API_BASE_URL;
  if (envUrl && typeof envUrl === "string" && envUrl.trim() !== "") {
    let base = envUrl.trim();
    if (!base.startsWith("http://") && !base.startsWith("https://")) {
      base = `https://${base}`;
    }
    return base.endsWith("/api") ? base : `${base.replace(/\/$/, "")}/api`;
  }

  // 2. Runtime browser location detection for cloud hosts (e.g. Render, Vercel)
  if (typeof window !== "undefined" && window.location) {
    const host = window.location.hostname;
    if (host !== "localhost" && host !== "127.0.0.1") {
      // Auto-match Render blueprint naming (civicshield-frontend-xyz -> civicshield-backend-xyz)
      if (host.includes("frontend")) {
        const backendHost = host.replace("frontend", "backend");
        return `https://${backendHost}/api`;
      }
      // If hosted on custom domain or single host, use origin/api
      return `${window.location.origin}/api`;
    }
  }

  // 3. Fallback for local development
  return "http://localhost:8000/api";
}

const API_BASE = getApiBaseUrl();

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

export async function analyzeText(
  inputType: "url" | "text",
  content: string,
  mode: AnalysisMode = "STATIC"
): Promise<AnalysisResult> {
  const form = new FormData();
  form.append("input_type", inputType);
  form.append("content", content);
  form.append("analysis_mode", mode);

  const response = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    body: form,
  });

  if (!response.ok) {
    const detail = await response.json().catch(() => ({ detail: "Unknown error" }));
    throw new ApiError(response.status, detail.detail || "Analysis failed");
  }

  return response.json() as Promise<AnalysisResult>;
}

export async function analyzeFile(
  inputType: "image" | "pdf",
  file: File,
  mode: AnalysisMode = "STATIC"
): Promise<AnalysisResult> {
  const form = new FormData();
  form.append("input_type", inputType);
  form.append("file", file, file.name);
  form.append("analysis_mode", mode);

  const response = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    body: form,
  });

  if (!response.ok) {
    const detail = await response.json().catch(() => ({ detail: "Unknown error" }));
    throw new ApiError(response.status, detail.detail || "Analysis failed");
  }

  return response.json() as Promise<AnalysisResult>;
}

export async function healthCheck(): Promise<{ status: string; ml_model_loaded: boolean; intel_providers?: Record<string, boolean> }> {
  const response = await fetch(`${API_BASE}/health`);
  if (!response.ok) throw new ApiError(response.status, "Health check failed");
  return response.json();
}
