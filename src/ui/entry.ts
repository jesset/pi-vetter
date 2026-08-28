import { Text } from "@earendil-works/pi-tui";

export interface ReportEntryData {
  markdown: string;
}

/**
 * Renders pi-vetter transcript entries. Structurally compatible with
 * pi's EntryRenderer<ReportEntryData>; kept loose so it is unit-testable
 * without a Theme instance.
 */
export function reportEntryRenderer(
  entry: { data?: ReportEntryData },
  _options: { expanded?: boolean },
  _theme: unknown,
) {
  const markdown = entry.data?.markdown ?? "";
  return new Text(markdown);
}
