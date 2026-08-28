type Phase = "idle" | "resolving" | "vetting";

/** Renderable progress state for the evaluation widget (setWidget takes string[]). */
export class ProgressTracker {
  private phase: Phase = "idle";
  private total = 0;
  private done = 0;
  private current: string | null = null;

  constructor(private readonly title: string) {}

  startResolve(total: number): void {
    this.phase = "resolving";
    this.total = total;
    this.done = 0;
    this.current = null;
  }

  start(total: number): void {
    this.phase = "vetting";
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
    if (this.phase === "idle") return [`${this.title}…`];
    const label = this.phase === "resolving" ? "resolving packages" : "vetting";
    const base =
      this.done >= this.total
        ? `${this.title}: ${label} (${this.done}/${this.total}) done`
        : `${this.title}: ${label} (${this.done}/${this.total})`;
    return this.current ? [base, `→ ${this.current}`] : [base];
  }
}
