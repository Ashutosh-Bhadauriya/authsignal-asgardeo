import { z } from "zod";

export const asgardeoAuthRequestSchema = z
  .object({
    actionType: z.string().optional(),
    flowId: z.string().min(1),
    requestId: z.string().optional(),
    allowedOperations: z
      .array(z.object({ op: z.string() }).passthrough())
      .optional(),
    event: z
      .object({
        user: z
          .object({
            id: z.string().optional(),
            username: z.string().optional(),
            email: z.string().optional(),
            claims: z.record(z.unknown()).optional()
          })
          .optional()
      })
      .passthrough()
      .optional()
  })
  .passthrough();

export type AsgardeoAuthRequest = z.infer<typeof asgardeoAuthRequestSchema>;

export type AsgardeoActionStatus = "SUCCESS" | "FAILED" | "INCOMPLETE" | "ERROR";

export type AsgardeoAuthResponse =
  | { actionStatus: "SUCCESS" }
  | { actionStatus: "INCOMPLETE"; operations: Array<{ op: string; url: string }> }
  | { actionStatus: "FAILED"; failureReason: string; failureDescription: string }
  | { actionStatus: "ERROR"; errorCode: string; errorDescription: string };
