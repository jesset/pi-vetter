export interface PoolOptions<T> {
  concurrency: number;
  onItemStart?: (item: T) => void;
  onItemError?: (item: T, error: unknown) => void;
}

/**
 * Bounded-concurrency worker pool over a static list. A failing item does not
 * stop the others; failures are surfaced through onItemError.
 */
export async function runPool<T>(
  items: readonly T[],
  run: (item: T) => Promise<void>,
  options: PoolOptions<T>,
): Promise<void> {
  const queue = [...items];
  const worker = async (): Promise<void> => {
    for (let item = queue.shift(); item !== undefined; item = queue.shift()) {
      options.onItemStart?.(item);
      try {
        await run(item);
      } catch (error) {
        options.onItemError?.(item, error);
      }
    }
  };
  const workers = Array.from({ length: Math.min(options.concurrency, items.length) }, worker);
  await Promise.all(workers);
}
