import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types";
import { logger } from "@/lib/logger";

export interface AuditEventInput {
  userId: string | null;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Best-effort audit logger persisted to `public.audit_logs`.
 * Failures are logged structurally without interrupting primary user workflows.
 */
export class AuditRepository {
  constructor(private readonly db: SupabaseClient<Database>) {}

  public async record(event: AuditEventInput): Promise<void> {
    const { error } = await this.db.from("audit_logs").insert({
      user_id: event.userId,
      action: event.action,
      resource_type: event.resourceType,
      resource_id: event.resourceId ?? null,
      metadata: event.metadata ?? {},
    });

    if (error) {
      logger.warn("Failed to persist audit log event", {
        action: event.action,
        resourceType: event.resourceType,
        error: error.message,
      });
    }
  }
}
