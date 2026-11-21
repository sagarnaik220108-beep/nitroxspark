import type { SupabaseClient } from "@supabase/supabase-js";
import type { CustomRuleRow, Database } from "@/types";
import { ConflictError, InternalServerError, NotFoundError } from "@/utils";

type CustomRuleInsert = Database["public"]["Tables"]["custom_rules"]["Insert"];

export class CustomRuleRepository {
  constructor(private readonly db: SupabaseClient<Database>) {}

  public async listEnabledByUser(userId: string): Promise<CustomRuleRow[]> {
    const { data, error } = await this.db
      .from("custom_rules")
      .select("*")
      .eq("user_id", userId)
      .eq("enabled", true)
      .order("created_at", { ascending: false });

    if (error) {
      throw new InternalServerError(
        "Failed to load custom security rules",
        error.message
      );
    }

    return data ?? [];
  }

  public async listAllByUser(userId: string): Promise<CustomRuleRow[]> {
    const { data, error } = await this.db
      .from("custom_rules")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });

    if (error) {
      throw new InternalServerError(
        "Failed to list custom security rules",
        error.message
      );
    }

    return data ?? [];
  }

  public async create(payload: CustomRuleInsert): Promise<CustomRuleRow> {
    const { data, error } = await this.db
      .from("custom_rules")
      .insert(payload)
      .select()
      .single();

    if (error) {
      if (error.code === "23505") {
        throw new ConflictError(
          `A custom rule with key '${payload.rule_key}' already exists`
        );
      }
      throw new InternalServerError(
        "Failed to create custom security rule",
        error.message
      );
    }

    return data;
  }

  public async delete(ruleId: string, userId: string): Promise<void> {
    const { data, error } = await this.db
      .from("custom_rules")
      .delete()
      .eq("id", ruleId)
      .eq("user_id", userId)
      .select("id")
      .maybeSingle();

    if (error) {
      throw new InternalServerError(
        "Failed to delete custom security rule",
        error.message
      );
    }
    if (!data) {
      throw new NotFoundError("CustomRule", ruleId);
    }
  }
}
