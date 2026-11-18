export function formatMarkdown(text: string): string {
  if (!text) return '';

  // 1. Escape HTML first to prevent XSS
  let safe = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

  // 2. Inline code (must be before bold/italic to avoid parsing * inside code)
  safe = safe.replace(
    /`([^`]+)`/g,
    '<code class="bg-[#0a0e0a] border border-[#00ff00] px-1.5 py-0.5 rounded text-xs font-mono text-[#00ff00]">$1</code>'
  );

  // 3. Bold
  safe = safe.replace(
    /\*\*(.*?)\*\*/g,
    '<strong class="font-bold text-[#00ff00]">$1</strong>'
  );

  // 4. Italic
  safe = safe.replace(
    /\*(.*?)\*/g,
    '<em class="italic text-[#00aa00]">$1</em>'
  );

  // 5. Strikethrough
  safe = safe.replace(
    /~~(.*?)~~/g,
    '<span class="line-through text-[#00aa00]">$1</span>'
  );

  // 6. URLs (make them clickable)
  safe = safe.replace(
    /(https?:\/\/[^\s<]+)/g,
    '<a href="$1" target="_blank" rel="noopener noreferrer" class="text-[#00ff00] underline hover:text-[#00aa00] transition-colors break-all">$1</a>'
  );

  // 7. Convert newlines to <br> for proper multi-line spacing
  safe = safe.replace(/\n/g, '<br>');

  return safe;
}