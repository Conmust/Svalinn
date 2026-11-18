/// <reference types="svelte" />
/// <reference types="vite/client" />

declare module '*.css' {
  const content: string;
  export default content;
}
interface ImportMetaEnv {
  /** Default Svalinn server address, e.g. https://chat.example.com */
  readonly VITE_API_URL?: string;
}
