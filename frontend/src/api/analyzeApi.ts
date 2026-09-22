/**
 * CivicShield — API Client
 * Typed fetch wrapper for the FastAPI backend.
 */

import type { AnalysisResult, InputType } from "../types/analysis";

const API_BASE = "http://localhost:8000/api";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function analyzeText(
  inputType: "url" | "text",
  content: string
): Promise<AnalysisResult> {
  const form = new FormData();
  form.append("input_type", inputType);
  form.append("content", content);

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
  file: File
): Promise<AnalysisResult> {
  const form = new FormData();
  form.append("input_type", inputType);
  form.append("file", file, file.name);

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

export async function healthCheck(): Promise<{ status: string; ml_model_loaded: boolean }> {
  const response = await fetch(`${API_BASE}/health`);
  if (!response.ok) throw new ApiError(response.status, "Health check failed");
  return response.json();
}
