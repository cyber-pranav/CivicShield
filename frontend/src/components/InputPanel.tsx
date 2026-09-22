import { useState, useRef, useCallback } from "react";
import type { InputType } from "../types/analysis";

interface Props {
  onSubmitText: (inputType: "url" | "text", content: string) => void;
  onSubmitFile: (inputType: "image" | "pdf", file: File) => void;
  loading: boolean;
}

export function InputPanel({ onSubmitText, onSubmitFile, loading }: Props) {
  const [activeTab, setActiveTab] = useState<InputType>("url");
  const [urlValue, setUrlValue] = useState("");
  const [textValue, setTextValue] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSubmit = () => {
    if (activeTab === "url") {
      if (!urlValue.trim()) return;
      onSubmitText("url", urlValue.trim());
    } else if (activeTab === "text") {
      if (!textValue.trim()) return;
      onSubmitText("text", textValue.trim());
    } else if (activeTab === "image" || activeTab === "pdf") {
      if (!file) return;
      onSubmitFile(activeTab, file);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.[0]) setFile(e.target.files[0]);
  };

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const dropped = e.dataTransfer.files[0];
      if (dropped) setFile(dropped);
    },
    []
  );

  const isSubmittable =
    (activeTab === "url" && urlValue.trim()) ||
    (activeTab === "text" && textValue.trim()) ||
    ((activeTab === "image" || activeTab === "pdf") && file);

  const tabs: { key: InputType; label: string }[] = [
    { key: "url", label: "🔗 URL" },
    { key: "text", label: "💬 Message" },
    { key: "image", label: "🖼 Image" },
    { key: "pdf", label: "📄 PDF" },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Tab switcher */}
      <div className="tab-group">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            className={`tab-btn ${activeTab === tab.key ? "active" : ""}`}
            onClick={() => {
              setActiveTab(tab.key);
              setFile(null);
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* URL input */}
      {activeTab === "url" && (
        <div>
          <input
            type="url"
            id="url-input"
            placeholder="https://..."
            value={urlValue}
            onChange={(e) => setUrlValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            style={{ fontSize: "0.9rem" }}
            autoComplete="off"
            spellCheck={false}
          />
          <div
            style={{
              marginTop: 6,
              fontSize: "0.75rem",
              color: "var(--text-muted)",
            }}
          >
            Paste the URL from an SMS, WhatsApp message, or email. The URL will
            NOT be visited — only the URL string is analysed.
          </div>
        </div>
      )}

      {/* Text / message input */}
      {activeTab === "text" && (
        <div>
          <textarea
            id="text-input"
            placeholder="Paste the full SMS, WhatsApp message, or email text here…"
            value={textValue}
            onChange={(e) => setTextValue(e.target.value)}
            rows={8}
          />
          <div
            style={{
              marginTop: 6,
              fontSize: "0.75rem",
              color: "var(--text-muted)",
            }}
          >
            All text is processed locally. Do not paste sensitive passwords or
            OTPs.
          </div>
        </div>
      )}

      {/* Image upload */}
      {activeTab === "image" && (
        <div>
          <div
            className={`file-drop ${dragging ? "dragging" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <div className="file-drop-icon">🖼</div>
            {file ? (
              <div className="file-selected">
                <span>📎</span>
                <span>{file.name}</span>
                <span
                  style={{
                    marginLeft: "auto",
                    fontSize: "0.72rem",
                    color: "var(--text-muted)",
                  }}
                >
                  {(file.size / 1024).toFixed(0)} KB
                </span>
              </div>
            ) : (
              <div className="file-drop-label">
                Drag & drop or <span>click to upload</span> a screenshot
                <br />
                <span
                  style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}
                >
                  JPEG · PNG · BMP · TIFF (max 5 MB)
                </span>
              </div>
            )}
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept="image/jpeg,image/png,image/bmp,image/tiff,image/webp"
            style={{ display: "none" }}
            onChange={handleFileChange}
          />
          <div
            style={{
              marginTop: 6,
              fontSize: "0.75rem",
              color: "var(--text-muted)",
            }}
          >
            OCR will extract text from the screenshot. Requires Tesseract to be
            installed on the server.
          </div>
        </div>
      )}

      {/* PDF upload */}
      {activeTab === "pdf" && (
        <div>
          <div
            className={`file-drop ${dragging ? "dragging" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <div className="file-drop-icon">📄</div>
            {file ? (
              <div className="file-selected">
                <span>📎</span>
                <span>{file.name}</span>
                <span
                  style={{
                    marginLeft: "auto",
                    fontSize: "0.72rem",
                    color: "var(--text-muted)",
                  }}
                >
                  {(file.size / 1024).toFixed(0)} KB
                </span>
              </div>
            ) : (
              <div className="file-drop-label">
                Drag & drop or <span>click to upload</span> a PDF document
                <br />
                <span
                  style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}
                >
                  PDF only · max 10 MB · PDFs are NOT executed
                </span>
              </div>
            )}
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept="application/pdf"
            style={{ display: "none" }}
            onChange={handleFileChange}
          />
        </div>
      )}

      {/* Submit button */}
      <button
        id="analyze-btn"
        className="btn-primary"
        onClick={handleSubmit}
        disabled={!isSubmittable || loading}
        style={{ alignSelf: "flex-start" }}
      >
        {loading ? (
          <>
            <span className="spinner" />
            Analysing…
          </>
        ) : (
          <>🔍 Analyse</>
        )}
      </button>
    </div>
  );
}
