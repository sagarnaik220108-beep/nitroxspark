import type { SupabaseClient } from "@supabase/supabase-js";
import type { AttackSimulationRow, Database } from "@/types";
import { InternalServerError } from "@/utils";

type SimulationInsert =
  Database["public"]["Tables"]["attack_simulations"]["Insert"];

export class SimulationRepository {
  constructor(private readonly db: SupabaseClient<Database>) {}

  public async createMany(
    rows: SimulationInsert[]
  ): Promise<AttackSimulationRow[]> {
    if (rows.length === 0) return [];

    const { data, error } = await this.db
      .from("attack_simulations")
      .insert(rows)
      .select();

    if (error || !data) {
      throw new InternalServerError(
        "Failed to persist attack simulations",
        error?.message
      );
    }

    return data;
  }

  public async findByScanId(
    scanId: string,
    userId: string
  ): Promise<AttackSimulationRow[]> {
    const { data, error } = await this.db
      .from("attack_simulations")
      .select("*")
      .eq("scan_id", scanId)
      .eq("user_id", userId)
      .order("created_at", { ascending: false });

    if (error) {
      throw new InternalServerError(
        "Failed to fetch attack simulations",
        error.message
      );
    }

    return data ?? [];
  }
}
