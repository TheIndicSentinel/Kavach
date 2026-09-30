# Kavach — Market Research

*Desk research as of 2026-09-29. Read-only web research via subagents. Much of the evidence is vendor marketing, law-firm summaries or small surveys — treat claims marked UNVERIFIED accordingly and confirm regulatory dates against primary RBI / MeitY sources before relying on them. Name-clearance findings are held privately and are not recorded here.*

## Summary

- **Agent authorization is becoming infrastructure.** AWS Bedrock AgentCore Policy (GA March 2026) ships Cedar-based policy enforcement on a gateway, with tool-call parameter conditions, a token vault, on-behalf-of flows and Mumbai-region availability. **Cedar + gateway + agent authorization alone is not a differentiated thesis.**
- **The apparent gap** is the combination of: authority derived from a *business transaction* (system-of-record mandate), purpose/consent binding (Account Aggregator / DPDP), customer-bound exact-action checks, credential brokering, on-prem deployment for regulated Indian lenders, and India-specific evidence. No vendor found combines these — but this is absence of evidence from search, and must be validated against vendor documentation and demos.
- **Indian regulated enterprises have a growing, dated AI-governance problem** (RBI recovery rules 1 Jan 2027; DPDP obligations 13 May 2027; RBI draft Model Risk Management guidance June 2026).
- **Positioning conclusion:** sell *authorization whose authority comes from the business transaction, customer and consent — not merely from agent identity.*

## Hypothesis scorecard

| Question | Confidence |
|---|---|
| Agent authorization is becoming a real platform capability | **Confirmed** |
| AWS is a serious technical reference competitor | **Confirmed** |
| Cedar/gateway alone is differentiated | **Disproved** |
| Business-record / mandate / consent authority is a meaningful gap | **Promising — needs competitive validation** |
| Indian regulated enterprises have a growing AI-governance problem | **Confirmed** |
| Collections is an attractive first agent workflow | **Strong hypothesis** |
| Decision Governance should lead revenue | **Strong hypothesis** |
| Platform vendors should be the Tier-1 channel | **Not established** |
| Direct NBFC / fintech selling should be tested | **Yes** |
| DPDP creates useful timing | **Confirmed** |
| RBI Model Risk Management guidance is an opportunity | **Confirmed as a draft; final impact unknown** |
| Economic buyer (CRO / model risk vs CISO / CTO) | **Hypothesis** — likely differs by wedge: Decision Governance → CRO / model risk / compliance; Agent Authorization → CISO / CTO / platform + risk |

## Competitive landscape

| Vendor | Category | Relevant capability | Overlap | India / on-prem | Source |
|---|---|---|---|---|---|
| AWS Bedrock AgentCore (Identity, Gateway, Policy) | IAM / authz / MCP gateway | Cedar policies on gateway, default-deny, tool-parameter inspection, NL→Cedar authoring, token vault, on-behalf-of OAuth. Policy GA 2026-03-03 | **High** | Cloud-only, AWS; Mumbai region | [Policy GA](https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/), [Cedar blog](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/), [Regions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-regions.html) |
| Microsoft Entra Agent ID | IAM | Agent identities, OAuth flows, Conditional Access for agents (GA April 2026). No purpose/consent binding found (UNVERIFIED) | Med | Cloud-first | [Learn](https://learn.microsoft.com/en-us/entra/agent-id/whats-new-agent-id) |
| Okta (Agent SSO, Cross App Access) | IAM | Agent SSO GA 2026-08-24, bundled in core SSO at no extra cost; XAA adopted as MCP enterprise-managed authorization | Med | SaaS | [Okta PR](https://www.okta.com/newsroom/press-releases/okta-brings-first-class-identity-to-ai-agents-with-agent-sso/) |
| Google Cloud (Agent Identity, Registry, Gateway) | IAM / gateway | SPIFFE-based agent identity; gateway policy for agent-to-agent and agent-to-tool (Next '26) | Med | Cloud-only | [Docs](https://docs.cloud.google.com/iam/docs/agent-identity-overview) |
| Aembit | Workload / agent IAM | Short-lived credentials, blended user+workload identity on MCP, no long-lived secrets | High (broker) | UNVERIFIED | [Aembit](https://aembit.io/) |
| CyberArk (Palo Alto Networks) | PAM / secrets | Secure AI Agents: lifecycle, secrets, audit | Med–High (broker) | Strong on-prem heritage | [CyberArk](https://www.cyberark.com/resources/product-insights-blog/cyberark-secure-ai-agents) |
| Keycard, Astrix (Cisco), Token Security and others | Agent / NHI identity | Agent identity and NHI governance | Med | UNVERIFIED | [CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisco-astrix-ai-agent-identity-market-cons/) |
| Permit.io, Cerbos, Oso, AuthZed | Fine-grained authz | Policy engines positioned for agent authorization; no mandate / broker / consent binding found | Med (engine) | Cerbos self-hostable | [Permit pricing](https://www.permit.io/pricing) |
| Zenity, Noma, Straiker, Palo Alto, CrowdStrike, SentinelOne, Check Point / Lakera, F5 | Runtime AI-agent security | Discovery, posture, injection and tool-abuse detection — detect-and-block, not source-of-record mandates | Low–Med | Mostly SaaS | [Straiker overview](https://www.straiker.ai/blog/top-agentic-ai-security-platforms) |
| Kong, Cloudflare, Docker, Lunar MCPX and others | MCP gateways | Tool-level access control and audit logs; coarse RBAC | Med (gateway) | Some self-hostable | [Lunar](https://www.lunar.dev/post/the-best-open-source-mcp-gateways-in-2026) |
| Credo AI and other GRC vendors | AI governance | Inventory, assessments, policy packs; not runtime enforcement | Low (complementary) | US-centric | [Review](https://co-aims.com/blog/credo-ai-review-2026-compliance-officers) |
| Google AP2; Visa / Mastercard agent pay; NPCI + Razorpay agentic UPI | Agent payment mandates | Signed mandates proving human authorization of purchases — payments protocol, not enterprise authorization. Agentic UPI announced Feb 2026 (pilot) | Concept only | India rails | [AP2](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol), [Razorpay](https://razorpay.com/blog/agentic-payments-and-npci/) |

**Closest competitors:** AgentCore (architecture), Aembit (credential brokering), Okta XAA / Entra (delegation), Cerbos / Permit (policy engine).
**Main competitive risk:** hyperscalers or IdPs add mandate-like task scoping; primitives are being bundled free (e.g., Okta Agent SSO).

### Indian players

No Indian vendor found doing agent authorization or credential brokering. Adjacent:

- **DPDP / consent tooling:** Concur, Leegality (Consentin), IDfy (Privy), Digio (CoTrust), Perfios, Think360 ConsenPro and others ([market map](https://harshithviswanath.substack.com/p/dpdpa-compliance-tools-in-india-the)).
- **AI security:** Deep Algorithms — ₹16 crore pre-Series A, agentic identity security ([source](https://indianstartupnews.com/news/ai-cybersecurity-startup-deep-algorithm-raises-rs-16-crore-funding-from-unicorn-india-ventures-11757268)).
- **Model risk / FREE-AI advisory:** Solytics Partners and others (product depth UNVERIFIED).
- **Ecosystem:** Sahamati recognised by RBI as the Account Aggregator SRO (2026-06-05); open questions on reconciling AA and DPDP consent-manager frameworks ([SCC](https://www.scconline.com/blog/post/2026/06/26/account-aggregator-consent-manager-paradox-dpdp-rules-fintech-sector/)).

### Category heat (M&A and funding)

Palo Alto closed CyberArk (Feb 2026) and acquired Protect AI and Portkey; Cisco announced intent to acquire Astrix (May 2026); CrowdStrike acquired Pangea and SGNL; F5 acquired CalypsoAI; Zenity $125M Series C; Straiker $64M Series A; Noma $100M Series B. Apple acqui-hired the OPA / Styra team (Aug 2025). Implication: strategic acquirers exist for agent-identity specialists; incumbents are converging on the space.

## Demand in Indian BFSI

- **Framing:** RBI frames AI risk as accountability and explainability. Governor Malhotra (FIBAC, 11 Aug 2026): "DPDP compliance will not suffice"; banks remain fully accountable for vendor AI ([source](https://the420.in/rbi-governor-malhotra-dpdp-compliance-banks-six-ai-risks/)).
- **Adoption:** Zeta survey (40 C-suite executives, 18 banks/NBFCs; vendor survey, small sample): 70% run AI in production; security/privacy is the top barrier; only 20% call model risk management mature; comfort with AI suggestions but not with tasks having immediate operational consequences ([source](https://cfotech.in/story/indian-banks-push-ai-in-production-but-security-bites)).
- **Live agentic deployments (vendor claims):** voice collections (Gnani.ai — ~₹20 Cr/month recovered for an NBFC; Elision — Dvara KGFS), Sarvam voice AI with Mahindra Finance (UNVERIFIED scale), Bajaj Finance sales/service agents (UNVERIFIED), HDFC Bank EVA, Perfios agentic workflows. **Most are voice / FAQ / reminder bots without real credentials.** No documented public incidents found.
- **Vendors bundle their own controls:** Newgen, Perfios and Nucleus pitch governance guardrails inside their own agents; collections voice vendors market "RBI-compliant" bots. No partnerships between Indian LOS / LMS vendors and governance firms found; no RFP text requiring AI governance found.

## Regulatory timeline

| Instrument | Status | Key dates | Relevance | Source |
|---|---|---|---|---|
| DPDP Act 2023 + Rules 2025 | Rules notified 13 Nov 2025 | Consent Manager provisions 13 Nov 2026; main obligations 13 May 2027 | Purpose / consent limitation, safeguards, breach reporting | [India Data Law](https://indiadatalaw.org/deadlines/), [Sansa Legal](https://www.sansalegal.com/post/dpdp-act-2023-and-rules-2025-phased-implementation-timeline-and-business-compliance-deadlines) |
| RBI recovery conduct (Responsible Business Conduct amendment directions) | Final (6 Aug 2026) | **Effective 1 Jan 2027**; contact 08:00–19:00; call records 6 months; agent data access limited to recovery needs | Direct fit: mandate windows, data minimisation, evidence | [Business Standard](https://www.business-standard.com/finance/news/rbi-extends-recovery-norms-deadline-eases-certification-timeline-126080602037_1.html), [India Today](https://www.indiatoday.in/business/story/rbi-loan-recovery-rules-2026-ban-harassment-anonymous-calls-late-visits-2965510-2026-08-07) |
| RBI draft Model Risk Management guidance | Draft (24 Jun 2026); comments closed 24 Jul 2026; final pending | No effective date | Kill switch, autonomy tiering, third-party model accountability — anchor Decision Governance to its *direction* | [CorpLawUpdates](https://www.corplawupdates.in/updates/rbi-draft-guidance-model-risk-management-2026-ai-ml-banks-nbfcs), [RBI](https://m.rbi.org.in/Scripts/BS_ViewREwiseDraftDirections.aspx) |
| RBI FREE-AI | Committee report (13 Aug 2025), non-binding | — | Direction-setting | [Lexology](https://www.lexology.com/library/detail.aspx?g=cdd93d6c-fd28-4c12-ac23-33d7820439ab) |
| RBI Digital Lending Directions 2025 | In force (May 2025) | — | Consent and purpose limits in lending | [Legal500](https://www.legal500.com/developments/thought-leadership/the-rbis-digital-lending-directions-2025-a-unified-code-for-a-fragmented-sector/) |
| SEBI AI/ML guidelines | Chair said "soon" (Aug 2026); not final | — | Human oversight, kill switch (secondary market) | [ANI](https://aninews.in/news/business/sebi-to-soon-issue-aiml-guidelines-for-capital-markets-mandate-human-oversight-kill-switch-controls-chairman-pandey20260819121850/) |
| TRAI TCCCPR amendment | Notified 12 Feb 2025; AI-call rules reportedly under consideration (Sep 2026) | — | Consent / disclosure evidence for voice agents | [TRAI](https://trai.gov.in/sites/default/files/2025-02/Regulation_12022025.pdf) |
| MeitY India AI Governance Guidelines | Released 5 Nov 2025; voluntary | — | Confirms sectoral regulators (RBI) lead | [DSCI](https://www.dsci.in/resource/content/summary-india-ai-governance-guidelines) |
| IT Rules amendment (synthetically generated information) | Effective 20 Feb 2026 | — | Intermediaries; low relevance | [Mondaq](https://www.mondaq.com/india/new-technology/1791048/indias-new-frontier-in-digital-content-and-ai-regulation-navigating-the-synthetically-generated-information-regulation-under-the-information-technology-intermediary-guidelines-and-digital-media-ethics-code-amendment-rules-2026) |
| IRDAI AI guidance | Not found (UNVERIFIED) | — | — | — |

## Pricing signals (directional only)

- Developer-tier authorization: Permit.io from ~$5–25/month; Cerbos Hub from $25/month; Oso $149/month startup tier ([Oso](https://www.osohq.com/learn/permitio-alternatives)).
- Secrets / PAM: Vault Enterprise reportedly ~$50–150K/year for small deployments ([Infisical](https://infisical.com/blog/hashicorp-vault-pricing)); CyberArk quote-based.
- AI governance: Credo AI third-party estimates ~$30–400K/year.
- Identity is being bundled free (Okta Agent SSO).
- **No Indian BFSI deal-size data found.** Pricing is to be tested, not assumed. Candidate units: per governed workflow, per institution / environment, platform / OEM licence. **Never per decision.**

## Implications for the plan

1. **Decision Governance leads revenue**, anchored to the *direction* of RBI's draft Model Risk Management guidance (not to its final issuance, which is pending).
2. **Collections is the first agent workflow.** The recovery rules make data-access brokering, time windows and borrower-bound mandates concrete. Differentiate on independent, cross-vendor enforcement and evidence — calling-hours scheduling alone is table stakes.
3. **Position against AWS by interoperating:** cloud-neutral, on-prem, Cedar-compatible; the differentiator is source-of-record mandates plus consent and Indian regulatory context.
4. **Vendor channel is test-in-parallel, not relied upon.**
5. **Charge for evidence, on-prem control and packs — not identity.**

## Open validation questions (for later customer conversations)

- Who owns the budget for AI governance and model risk — CRO, CISO, CTO or CDO?
- How are lenders preparing for the RBI draft Model Risk Management guidance (kill switch, autonomy tiers, vendor-model validation)?
- How do lenders prove to RBI inspectors today that a model or bot stayed within limits?
- Which AI agents run in collections and service, what data can they reach, and how is it limited?
- How will lenders enforce the 1 Jan 2027 recovery rules across multiple vendors? Do most lenders use more than one collections vendor?
- Do bank customers ask platform vendors for independent AI-governance evidence in RFPs or due diligence? Would vendors embed, pay for, or build this?
