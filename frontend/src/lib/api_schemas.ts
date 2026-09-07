import { z } from "zod";

/**
 * Request schemas for every mutating console API. Kept strict: unknown
 * fields are stripped, strings bounded, identifiers constrained so CLI
 * arguments can never contain option-looking values (leading "-").
 */

const idString = z
  .string()
  .min(1)
  .max(256)
  .refine((s) => !s.startsWith("-"), "identifiers must not start with '-'");

const actionId = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9_.:-]+$/, "invalid identifier")
  .refine((s) => !s.startsWith("-"), "identifiers must not start with '-'");

/** Body of `POST /api/authorize` (simulator requests). */
export const authorizeSchema = z.object({
  principalType: z.enum(["user", "agent"]).default("user"),
  uid: idString,
  parentUid: idString.optional(),
  tool: actionId,
  operation: actionId.optional(),
  resourceType: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9_]+$/, "entity type must be alphanumeric/underscore"),
  resourceId: idString,
  args: z.record(z.string(), z.unknown()).default({}),
  session: z.record(z.string(), z.unknown()).default({}),
});

/** Body of `POST /api/delegate`. */
export const delegateSchema = z.object({
  from: idString,
  to: idString,
  actions: z.array(actionId).min(1).max(32),
  resources: z
    .array(
      z
        .string()
        .min(1)
        .max(256)
        .regex(/^[A-Za-z0-9_:#*-]+$/, "invalid resource identifier")
        .refine((s) => !s.startsWith("-"), "identifiers must not start with '-'")
    )
    .min(1)
    .max(32),
  ttlSeconds: z.number().int().min(30).max(86_400).default(900),
});

/** Body of `POST /api/verify`. */
export const verifySchema = z.object({
  token: z.string().min(16).max(16_384),
  keysFile: z
    .string()
    .min(1)
    .max(1024)
    .refine((s) => !s.includes("..") && !s.startsWith("-"), "invalid path"),
});

/** Query parameters of `GET /api/log`. */
export const logQuerySchema = z.object({
  n: z.coerce.number().int().min(1).max(500).default(20),
  principal: z.string().max(256).optional(),
  action: z.string().max(256).optional(),
});

/** Success payload of `GET /api/log`. */
export const logResponseSchema = z.object({
  records: z.array(
    z.object({
      id: z.string(),
      timestamp: z.string(),
      effect: z.string(),
      policies: z.array(z.string()),
      principal: z.string(),
      action: z.string(),
      resource: z.string(),
      reasons: z.array(z.string()),
      trace_id: z.string().optional(),
      tenant_id: z.string().optional(),
    })
  ),
});

/** Success payload of `POST /api/delegate`. */
export const delegateResponseSchema = z.object({
  token: z.string(),
});

/** Success payload of `POST /api/authorize`. */
export const decisionResponseSchema = z.object({
  effect: z.enum(["allow", "deny"]),
  policies: z.array(z.string()),
  reasons: z.array(z.string()),
  request: z.record(z.string(), z.unknown()),
  raw: z.record(z.string(), z.unknown()),
});

/** Error payload returned by console API routes on failure. */
export const errorResponseSchema = z.object({
  error: z.string().optional(),
  kind: z.string().optional(),
});

/** Parse a JSON body against a schema; returns a discriminated result. */
export async function parseJsonBody<S extends z.ZodType>(
  request: Request,
  schema: S
): Promise<
  | { ok: true; data: z.infer<S> }
  | { ok: false; status: 400; error: string }
> {
  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return { ok: false, status: 400, error: "request body must be JSON" };
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const where = issue?.path?.length ? `${issue.path.join(".")}: ` : "";
    return {
      ok: false,
      status: 400,
      error: `${where}${issue?.message ?? "validation failed"}`,
    };
  }
  return { ok: true, data: parsed.data };
}
