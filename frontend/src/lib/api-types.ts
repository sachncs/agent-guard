export interface AuthorizeRequestBody {
  principalType: "user" | "agent";
  uid: string;
  parentUid?: string;
  tool: string;
  operation?: string;
  resourceType: string;
  resourceId: string;
  args?: Record<string, unknown>;
  session?: Record<string, unknown>;
}

/** Mirrors `Decision` from the agentguard SDK. */
export interface DecisionDto {
  effect: "allow" | "deny";
  policies: string[];
  reasons: string[];
  request: Record<string, unknown>;
  raw: Record<string, unknown>;
  trace_id?: string;
  span_id?: string;
  tenant_id?: string;
  step_up?: { acr_values: string; amr_values: string };
}

/** Mirrors a hash-chained audit record (DecisionRecord v2). */
export interface LogRecord {
  id: string;
  timestamp: string;
  effect: string;
  policies: string[];
  principal: string;
  action: string;
  resource: string;
  reasons: string[];
  trace_id?: string;
  tenant_id?: string;
}

export interface DelegateRequestBody {
  from: string;
  to: string;
  actions: string[];
  resources: string[];
  ttlSeconds: number;
}

export interface VerifyRequestBody {
  token: string;
  keysFile: string;
}
