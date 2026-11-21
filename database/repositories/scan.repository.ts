import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database, ScanRow } from "@/types";
import { InternalServerError, NotFoundError } from "@/utils";

type ScanInsert = Database["public"]["Tables"]["scans"]["Insert"];

export class ScanRepository {
  constructor(private readonly db: SupabaseClient<Database>) {}

  public async create(payload: ScanInsert): Promise<ScanRow> {
    const { data, error } = await this.db
      .from("scans")
      .insert(payload)
      .select()
      .single();

    if (error || !data) {
      throw new InternalServerError("Failed to persist scan record", error?.message);
    }

    return data;
  }

  public async findById(scanId: string, userId: string): Promise<ScanRow> {
    const { data, error } = await this.db
      .from("scans")
      .select("*")
      .eq("id", scanId)
      .eq("user_id", userId)
      .maybeSingle();

    if (error) {
      throw new InternalServerError("Failed to query scan", error.message);
    }
    if (!data) {
      throw new NotFoundError("Scan", scanId);
    }

    return data;
  }

  public async listByUser(
    userId: string,
    page: number,
    pageSize: number
  ): Promise<{ items: ScanRow[]; total: number }> {
    const from = (page - 1) * pageSize;
    const to = from + pageSize - 1;

    const { data, error, count } = await this.db
      .from("scans")
      .select("*", { count: "exact" })
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .range(from, to);

    if (error) {
      throw new InternalServerError("Failed to list scans", error.message);
    }

    return {
      items: data ?? [],
      total: count ?? 0,
    };
  }

  public async delete(scanId: string, userId: string): Promise<void> {
    const { data, error } = await this.db
      .from("scans")
      .delete()
      .eq("id", scanId)
      .eq("user_id", userId)
      .select("id")
      .maybeSingle();

    if (error) {
      throw new InternalServerError("Failed to delete scan", error.message);
    }
    if (!data) {
      throw new NotFoundError("Scan", scanId);
    }
  }
}
