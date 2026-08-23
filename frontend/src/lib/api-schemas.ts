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

export const verifySchema = z.object({
  token: z.string().min(16).max(16_384),
  keysFile: z
    .string()
    .min(1)
    .max(1024)
    .refine((s) => !s.includes("..") && !s.startsWith("-"), "invalid path"),
});

export const logQuerySchema = z.object({
  n: z.coerce.number().int().min(1).max(500).default(20),
  principal: z.string().max(256).optional(),
  action: z.string().max(256).optional(),
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
