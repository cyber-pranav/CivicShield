/**
 * CivicShield — API Client
 * Typed fetch wrapper for the FastAPI backend.
 */

import type { AnalysisResult, AnalysisMode } from "../types/analysis";

const API_BASE = "http://localhost:8000/api";

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
