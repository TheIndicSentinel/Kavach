export function buildPartnerSampleRequest(now = new Date()): string {
  const timestamp = now.toISOString();
  return JSON.stringify(
    {
      model_id: "credit-underwriting-v1",
      model_version: "1.0.0",
      purpose: "credit_decision",
      consent: {
        purpose_id: "credit_decision",
        timestamp,
      },
      input: {
        application_ref: "PL-IN-2026-0048217",
        product_code: "personal_loan_unsecured",
        customer_segment: "salaried",
        state_code: "MH",
        bureau_score: 712,
        credit_score: 712,
        monthly_income_inr: 92000,
        income: 92000,
        existing_emi_inr: 18500,
        proposed_emi_inr: 11200,
        loan_amount: 450000,
        tenure_months: 48,
        employment_years: 4,
        employment_type: "private_sector",
        debt_ratio: 0.322,
        bureau_pull_date: "2026-08-14",
        informal_sector: false,
      },
      score: 0.74,
      confidence: 0.82,
      decision_time: timestamp,
      correlation_id: "console-partner-pl-mh-001",
      idempotency_key: "console-partner-pl-mh-001",
    },
    null,
    2,
  );
}

export const ACTIVE_MODEL = {
  modelId: "credit-underwriting-v1",
  version: "1.0.0",
  sector: "finance",
  packId: "finance-v0",
  governanceMode: "shadow",
  jurisdiction: "IN",
} as const;
