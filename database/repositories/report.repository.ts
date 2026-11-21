import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database, SecurityReportRow } from "@/types";
import { InternalServerError, NotFoundError } from "@/utils";

type ReportInsert = Database["public"]["Tables"]["security_reports"]["Insert"];

export class ReportRepository {
  constructor(private readonly db: SupabaseClient<Database>) {}

  public async create(payload: ReportInsert): Promise<SecurityReportRow> {
    const { data, error } = await this.db
      .from("security_reports")
      .insert(payload)
      .select()
      .single();

    if (error || !data) {
      throw new InternalServerError(
        "Failed to persist security report",
        error?.message
      );
    }

    return data;
  }

  public async findById(
    reportId: string,
    userId: string
  ): Promise<SecurityReportRow> {
    const { data, error } = await this.db
      .from("security_reports")
      .select("*")
      .eq("id", reportId)
      .eq("user_id", userId)
      .maybeSingle();

    if (error) {
      throw new InternalServerError(
        "Failed to fetch security report",
        error.message
      );
    }
    if (!data) {
      throw new NotFoundError("SecurityReport", reportId);
    }

    return data;
  }

  public async listByUser(
    userId: string,
    page: number,
    pageSize: number
  ): Promise<{ items: SecurityReportRow[]; total: number }> {
    const from = (page - 1) * pageSize;
    const to = from + pageSize - 1;

    const { data, error, count } = await this.db
      .from("security_reports")
      .select("*", { count: "exact" })
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .range(from, to);

    if (error) {
      throw new InternalServerError(
        "Failed to list security reports",
        error.message
      );
    }

    return {
      items: data ?? [],
      total: count ?? 0,
    };
  }

  public async delete(reportId: string, userId: string): Promise<void> {
    const { data, error } = await this.db
      .from("security_reports")
      .delete()
      .eq("id", reportId)
      .eq("user_id", userId)
      .select("id")
      .maybeSingle();

    if (error) {
      throw new InternalServerError(
        "Failed to delete security report",
        error.message
      );
    }
    if (!data) {
      throw new NotFoundError("SecurityReport", reportId);
    }
  }
}
