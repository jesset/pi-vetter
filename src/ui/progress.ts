type Phase = "idle" | "resolving" | "vetting";
type RowState = "pending" | "inflight" | "done";

const MARK: Record<RowState, string> = { pending: "·", inflight: "…", done: "✓" };

/** Renderable progress state for the evaluation widget (setWidget takes string[]). */
export class ProgressTracker {
  private phase: Phase = "idle";
  private names: string[] = [];
  private states: RowState[] = [];
  private done = 0;

  constructor(private readonly title: string) {}

  startResolve(names: string[]): void {
    this.reset("resolving", names);
  }

  start(names: string[]): void {
    this.reset("vetting", names);
  }

  item(name: string): void {
    const i = this.names.findIndex((n, i) => n === name && this.states[i] === "pending");
    if (i >= 0) this.states[i] = "inflight";
  }

  tick(name: string): void {
    const i = this.names.findIndex((n, i) => n === name && this.states[i] !== "done");
    if (i >= 0) {
      this.states[i] = "done";
      this.done += 1;
    }
  }

  lines(): string[] {
    if (this.phase === "idle") return [`${this.title}…`];
    const label = this.phase === "resolving" ? "resolving packages" : "vetting";
    const base =
      this.done >= this.names.length
        ? `${this.title}: ${label} (${this.done}/${this.names.length}) done`
        : `${this.title}: ${label} (${this.done}/${this.names.length})`;
    return [base, ...this.names.map((n, i) => `${MARK[this.states[i] ?? "pending"]} ${n}`)];
  }

  private reset(phase: Phase, names: string[]): void {
    this.phase = phase;
    this.names = names;
    this.states = names.map(() => "pending");
    this.done = 0;
  }
}
