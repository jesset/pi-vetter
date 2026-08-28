/** Renderable progress state for the evaluation widget (setWidget takes string[]). */
export class ProgressTracker {
  private total = 0;
  private done = 0;
  private current: string | null = null;

  constructor(private readonly title: string) {}

  start(total: number): void {
    this.total = total;
    this.done = 0;
    this.current = null;
  }

  item(name: string): void {
    this.current = name;
  }

  tick(): void {
    this.done += 1;
    this.current = null;
  }

  lines(): string[] {
    if (this.total === 0) return [`${this.title}…`];
    const base =
      this.done >= this.total
        ? `${this.title} (${this.done}/${this.total}) done`
        : `${this.title} (${this.done}/${this.total})`;
    return this.current ? [base, `→ ${this.current}`] : [base];
  }
}
