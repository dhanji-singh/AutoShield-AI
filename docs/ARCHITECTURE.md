# Architecture and boundaries

```mermaid
flowchart TD
    UI["React scanner"] --> API["FastAPI worker"]
    API --> MCP["MCP scanner gateway"]
    MCP --> POLICY["ArmorIQ decision"]
    POLICY -->|"Allow"| CHECK["Scope, DNS, TLS and budget checks"]
    POLICY -->|"Block, hold or error"| STOP["Stop and retain evidence"]
    CHECK --> TARGET["Authorized HTTP origin"]
    TARGET --> REPORT["Response observations and hashes"]
    REPORT --> UI
```

The scanner's AI review receives a minimized summary after scanning; it cannot execute tools or change verdicts. Every request is evaluated separately. The readiness endpoint reports local prerequisites and historical outcomes, not authorization for a new request.

```mermaid
flowchart TD
    LOG["Juice Shop proxy log"] --> FIND["Detector finding"]
    FIND --> PROP["Trusted template proposal"]
    PROP --> COMP["Deterministic ModSecurity compiler"]
    COMP --> CAND["Candidate WAF"]
    CAND --> VALID["Syntax, benign cases and rule-ID evidence"]
    VALID --> PROMOTE["Explicit lab promotion"]
    PROMOTE --> ENFORCE["Enforcement WAF / rollback"]
```

The rule compiler handles supported SQLi patterns on `GET /rest/products/search`, parameter `q`. It does not consume arbitrary scanner findings or generate rules from model text. Generating a proposal and compiled artifact can be automated through the API. Installing candidate content and promoting validated rules remain explicit operator actions.

The separate DevOps MCP service runs five constrained lab tools. A deterministic capability policy and optional semantic veto run before ArmorIQ. Decisions are recorded before execution; local deterministic denials may add exact-request deny fingerprints. This is a deny cache, not general policy learning. Shell tools run only the three allowlisted capabilities using a sanitized child environment.
