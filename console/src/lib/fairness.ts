export type GroupMetric = {
  group_value: string;
  count: number;
  approval_rate: number;
  sample_sufficient: boolean;
  gap_from_reference?: number | null;
};

export type FlaggedGroup = {
  group_value: string;
  gap_from_reference: number;
  approval_rate: number;
  reference_approval_rate: number;
};

export type DisparityReport = {
  report_type: "disparity";
  attribute: string;
  min_sample_size: number;
  disparity_threshold: number;
  total_evaluated: number;
  overall_approval_rate: number;
  reference_group: string;
  groups: GroupMetric[];
  max_disparity_gap: number;
  flagged: FlaggedGroup[];
  generated_at: string;
};

export type InclusionReport = {
  report_type: "inclusion";
  segment_field: string;
  min_sample_size: number;
  total_evaluated: number;
  inclusion_count: number;
  inclusion_approval_rate: number;
  non_inclusion_count: number;
  non_inclusion_approval_rate: number;
  approval_gap: number;
  inclusion_sample_sufficient: boolean;
  non_inclusion_sample_sufficient: boolean;
  flagged: boolean;
  generated_at: string;
};

export type FairnessReport = DisparityReport | InclusionReport;

export function parseFairnessReport(raw: unknown): FairnessReport {
  if (!raw || typeof raw !== "object") {
    throw new Error("Report must be a JSON object");
  }
  const report = raw as { report_type?: string };
  if (report.report_type === "disparity") {
    return raw as DisparityReport;
  }
  if (report.report_type === "inclusion") {
    return raw as InclusionReport;
  }
  throw new Error('Unknown report_type — expected "disparity" or "inclusion"');
}

export function isDisparityReport(report: FairnessReport): report is DisparityReport {
  return report.report_type === "disparity";
}
