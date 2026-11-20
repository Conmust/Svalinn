<script lang="ts">
  // The "Svalinn Gauge" -- see README.md's "The Svalinn Gauge" section.
  // Polls the Tauri backend's `get_gauge_stats` command (apps/desktop/src-tauri/src/gauge.rs).
  //
  // The badge shows Svalinn's OWN footprint (just our process, comparable to
  // the README's memory target). Clicking it expands to the TOTAL across our
  // whole process tree -- our process plus every webview/GPU/network helper
  // -- broken down by which other processes it's tied to, since on Windows
  // that total is dominated by WebView2's own Chromium process tree rather
  // than anything Svalinn's own code is doing.
  import { onDestroy, onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';

  const POLL_INTERVAL_MS = 1500;
  const HISTORY_LENGTH = 30;

  interface ProcessGroup {
    name: string;
    process_count: number;
    memory_bytes: number;
  }

  interface GaugeStats {
    app_memory_bytes: number;
    app_cpu_percent: number;
    total_memory_bytes: number;
    total_cpu_percent: number;
    process_count: number;
    other_processes: ProcessGroup[];
  }

  let appMemoryMb: number | null = null;
  let appCpuPercent: number | null = null;
  let totalMemoryMb: number | null = null;
  let totalCpuPercent: number | null = null;
  let processCount: number | null = null;
  let otherProcesses: ProcessGroup[] = [];
  let unavailable = false;
  let expanded = false;

  // Ring buffer of recent app-memory samples (MB), oldest first, for the
  // optional sparkline the README calls for. Tracks the badge's own number
  // (app usage), not the total, since that's what's always visible.
  let history: number[] = [];

  let timer: ReturnType<typeof setInterval> | undefined;

  async function poll() {
    try {
      const stats = await invoke<GaugeStats>('get_gauge_stats');
      appMemoryMb = stats.app_memory_bytes / (1024 * 1024);
      appCpuPercent = stats.app_cpu_percent;
      totalMemoryMb = stats.total_memory_bytes / (1024 * 1024);
      totalCpuPercent = stats.total_cpu_percent;
      processCount = stats.process_count;
      otherProcesses = stats.other_processes;
      unavailable = false;

      history = [...history, appMemoryMb].slice(-HISTORY_LENGTH);
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

<!--
  Floats top-center over the whole window, pinned to the viewport rather
  than to either chat panel's header -- it's the same badge whether a
  channel, a DM, or nothing is open, and it doesn't shift when the roster
  opens/closes or the window resizes. This is also where each chat panel's
  header used to print a channel/DM name; that's gone now (ChatArea's,
  anyway -- see its header comment) in favor of the channel list's own
  highlight, which freed up this spot.
  The expanded detail panel drops straight down from the badge
  (`top-full`), so it stays anchored to the badge instead of a second
  hardcoded position.
-->
<div class="fixed top-2 left-1/2 -translate-x-1/2 z-[150]">
  <button
    type="button"
    class="px-2 py-1 bg-black border border-[#00aa00]/50 text-[#00ff00] text-xs font-mono hover:border-[#00ff00] transition-colors"
    on:click={() => (expanded = !expanded)}
    title="Svalinn Gauge -- click for details"
  >
    {#if unavailable}
      [ -- ]
    {:else if appMemoryMb === null}
      [ measuring... ]
    {:else}
      [ {appMemoryMb.toFixed(0)} MB | {(appCpuPercent ?? 0).toFixed(1)}% CPU ]
    {/if}
  </button>

  {#if expanded}
  <div
    class="absolute top-full left-1/2 -translate-x-1/2 mt-2 p-3 bg-black border border-[#00aa00]/50 text-[#00ff00] text-xs font-mono w-64 max-w-[90vw] space-y-2"
  >
    {#if unavailable}
      <div class="text-[#ffaa00]">Gauge unavailable in this environment.</div>
    {:else}
      <div class="text-[#00aa00]">Svalinn (app only)</div>
      <div class="flex justify-between pl-2"><span class="text-[#00aa00]">Memory (RSS)</span><span>{appMemoryMb?.toFixed(1) ?? '--'} MB</span></div>
      <div class="flex justify-between pl-2"><span class="text-[#00aa00]">CPU</span><span>{(appCpuPercent ?? 0).toFixed(1)}%</span></div>

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

      <div class="pt-2 border-t border-[#00aa00]/30 text-[#00aa00]">Total (incl. tied processes)</div>
      <div class="flex justify-between pl-2"><span class="text-[#00aa00]">Memory</span><span>{totalMemoryMb?.toFixed(1) ?? '--'} MB</span></div>
      <div class="flex justify-between pl-2"><span class="text-[#00aa00]">CPU</span><span>{(totalCpuPercent ?? 0).toFixed(1)}%</span></div>
      <div class="flex justify-between pl-2"><span class="text-[#00aa00]">Processes summed</span><span>{processCount ?? '--'}</span></div>

      {#if otherProcesses.length > 0}
        <div class="pl-2 space-y-0.5">
          {#each otherProcesses as group}
            <div class="flex justify-between text-[#006600]">
              <span>{group.name} ({group.process_count})</span>
              <span>{(group.memory_bytes / (1024 * 1024)).toFixed(1)} MB</span>
            </div>
          {/each}
        </div>
      {:else}
        <div class="pl-2 text-[#006600]">No other processes tied to this app right now.</div>
      {/if}

      {#if import.meta.env.DEV && appMemoryMb !== null}
        <div class="text-[#006600] pt-1 border-t border-[#00aa00]/30 space-y-0.5">
          <div>raw app RSS: {Math.round(appMemoryMb * 1024 * 1024).toLocaleString()} bytes</div>
          <div>methodology: "app" = our own process only; "total" = our process + every descendant OS process (webview/GPU/network helpers included)</div>
        </div>
      {/if}
    {/if}
  </div>
  {/if}
</div>
