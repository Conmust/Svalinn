<script lang="ts">
  // The "Svalinn Gauge" -- see README.md's "The Svalinn Gauge" section.
  // Polls the Tauri backend's `get_gauge_stats` command (apps/desktop/src-tauri/src/gauge.rs),
  // which sums RSS/CPU across our process and every child process (webview
  // helpers included), so the number reflects the whole app, not just the
  // Rust side of it.
  import { onDestroy, onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';

  const POLL_INTERVAL_MS = 1500;
  const HISTORY_LENGTH = 30;

  interface GaugeStats {
    memory_bytes: number;
    cpu_percent: number;
    process_count: number;
  }

  let memoryMb: number | null = null;
  let cpuPercent: number | null = null;
  let processCount: number | null = null;
  let unavailable = false;
  let expanded = false;

  // Ring buffer of recent memory samples (MB), oldest first, for the
  // optional sparkline the README calls for.
  let history: number[] = [];

  let timer: ReturnType<typeof setInterval> | undefined;

  async function poll() {
    try {
      const stats = await invoke<GaugeStats>('get_gauge_stats');
      memoryMb = stats.memory_bytes / (1024 * 1024);
      cpuPercent = stats.cpu_percent;
      processCount = stats.process_count;
      unavailable = false;

      history = [...history, memoryMb].slice(-HISTORY_LENGTH);
    } catch (e) {
      // Not running under Tauri (e.g. `vite dev` in a plain browser tab for
      // frontend-only work), or the native call itself failed. Either way,
      // show a plain dash instead of a broken/misleading readout.
      console.error('Svalinn Gauge: failed to read system stats', e);
      unavailable = true;
    }
  }

  onMount(() => {
    poll();
    timer = setInterval(poll, POLL_INTERVAL_MS);
  });

  onDestroy(() => {
    if (timer) clearInterval(timer);
  });

  function sparklinePoints(values: number[]): string {
    if (values.length < 2) return '';
    const max = Math.max(...values);
    const min = Math.min(...values);
    const range = max - min || 1;
    const width = 100;
    const height = 24;
    return values
      .map((v, i) => {
        const x = (i / (values.length - 1)) * width;
        const y = height - ((v - min) / range) * height;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  }
</script>

<button
  type="button"
  class="fixed bottom-2 left-2 z-[150] px-2 py-1 bg-black border border-[#00aa00]/50 text-[#00ff00] text-xs font-mono hover:border-[#00ff00] transition-colors"
  on:click={() => (expanded = !expanded)}
  title="Svalinn Gauge -- click for details"
>
  {#if unavailable}
    [ -- ]
  {:else if memoryMb === null}
    [ measuring... ]
  {:else}
    [ {memoryMb.toFixed(0)} MB | {(cpuPercent ?? 0).toFixed(1)}% CPU ]
  {/if}
</button>

{#if expanded}
  <div
    class="fixed bottom-10 left-2 z-[150] p-3 bg-black border border-[#00aa00]/50 text-[#00ff00] text-xs font-mono w-56 space-y-2"
  >
    {#if unavailable}
      <div class="text-[#ffaa00]">Gauge unavailable in this environment.</div>
    {:else}
      <div class="flex justify-between"><span class="text-[#00aa00]">Memory (RSS)</span><span>{memoryMb?.toFixed(1) ?? '--'} MB</span></div>
      <div class="flex justify-between"><span class="text-[#00aa00]">CPU</span><span>{(cpuPercent ?? 0).toFixed(1)}%</span></div>
      <div class="flex justify-between"><span class="text-[#00aa00]">Processes summed</span><span>{processCount ?? '--'}</span></div>
      {#if history.length >= 2}
        <svg viewBox="0 0 100 24" class="w-full h-6" preserveAspectRatio="none">
          <polyline
            points={sparklinePoints(history)}
            fill="none"
            stroke="#00ff00"
            stroke-width="1.5"
            vector-effect="non-scaling-stroke"
          />
        </svg>
        <div class="text-[#006600]">last {history.length} samples (~{((history.length * POLL_INTERVAL_MS) / 1000).toFixed(0)}s)</div>
      {/if}
      {#if import.meta.env.DEV && memoryMb !== null}
        <div class="text-[#006600] pt-1 border-t border-[#00aa00]/30 space-y-0.5">
          <div>raw RSS: {Math.round(memoryMb * 1024 * 1024).toLocaleString()} bytes</div>
          <div>methodology: sum of RSS/CPU across our process + every child OS process (webview helpers included)</div>
        </div>
      {/if}
    {/if}
  </div>
{/if}
