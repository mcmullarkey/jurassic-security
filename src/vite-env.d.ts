/// <reference types="vite/client" />

interface ImportMetaEnv {
  // Add any client-side environment variables here if needed
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}