import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types";
import { InternalServerError, NotFoundError } from "@/utils";

export type ProjectRiskLevel = "low" | "medium" | "high" | "critical";
export type ProjectStatus = "active" | "archived" | "paused";

/**
 * Strongly-typed row shape for `public.projects` (migration `003_complete_production_schema.sql`).
 */
export type ProjectRow = {
  id: string;
  user_id: string;
  name: string;
  slug: string;
  description: string | null;
  repository_url: string | null;
  primary_language: string;
  latest_security_score: number;
  risk_level: ProjectRiskLevel;
  status: ProjectStatus;
  created_at: string;
  updated_at: string;
};

export type ProjectInsert = {
  id?: string;
  user_id: string;
  name: string;
  slug: string;
  description?: string | null;
  repository_url?: string | null;
  primary_language?: string;
  latest_security_score?: number;
  risk_level?: ProjectRiskLevel;
  status?: ProjectStatus;
};

export type ProjectUpdate = {
  name?: string;
  slug?: string;
  description?: string | null;
  repository_url?: string | null;
  primary_language?: string;
  latest_security_score?: number;
  risk_level?: ProjectRiskLevel;
  status?: ProjectStatus;
};

/**
 * CamelCase domain model returned by `ProjectRepository`.
 */
export interface ProjectRecord {
  id: string;
  userId: string;
  name: string;
  slug: string;
  description: string | null;
  repositoryUrl: string | null;
  primaryLanguage: string;
  latestSecurityScore: number;
  riskLevel: ProjectRiskLevel;
  status: ProjectStatus;
  createdAt: string;
  updatedAt: string;
}

/**
 * Local typed Supabase schema view for `public.projects` so `ProjectRepository`
 * remains strictly typed without mutating shared database type definitions.
 */
export interface ProjectsTableSchema {
  public: {
    Tables: {
      projects: {
        Row: ProjectRow;
        Insert: ProjectInsert;
        Update: ProjectUpdate;
        Relationships: [];
      };
    };
    Views: Record<string, never>;
    Functions: Record<string, never>;
    Enums: Record<string, never>;
    CompositeTypes: Record<string, never>;
  };
}

export interface ProjectListParams {
  status?: ProjectStatus;
  riskLevel?: ProjectRiskLevel;
  search?: string;
  page?: number;
  pageSize?: number;
  sortBy?: "updated_at" | "created_at" | "latest_security_score" | "name";
  ascending?: boolean;
}

function toProjectsClient(
  db: SupabaseClient<Database> | SupabaseClient<ProjectsTableSchema>
): SupabaseClient<ProjectsTableSchema> {
  return db as unknown as SupabaseClient<ProjectsTableSchema>;
}

function mapRowToProject(row: ProjectRow): ProjectRecord {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    slug: row.slug,
    description: row.description,
    repositoryUrl: row.repository_url,
    primaryLanguage: row.primary_language,
    latestSecurityScore: row.latest_security_score,
    riskLevel: row.risk_level,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Converts an arbitrary project name into a URL-safe, lowercase slug.
 */
export function slugifyProjectName(name: string): string {
  const normalized = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return normalized.length > 0 ? normalized : "untitled-project";
}

/**
 * Data access repository for `public.projects`.
 * All queries are explicitly scoped to `user_id` in addition to Supabase RLS.
 */
export class ProjectRepository {
  private readonly db: SupabaseClient<ProjectsTableSchema>;

  constructor(
    supabase: SupabaseClient<Database> | SupabaseClient<ProjectsTableSchema>
  ) {
    this.db = toProjectsClient(supabase);
  }

  /**
   * Creates a new project row and returns the persisted domain model.
   */
  public async create(payload: ProjectInsert): Promise<ProjectRecord> {
    const { data, error } = await this.db
      .from("projects")
      .insert(payload)
      .select("*")
      .single();

    if (error || !data) {
      throw new InternalServerError(
        "Failed to create project",
        error?.message
      );
    }

    return mapRowToProject(data);
  }

  /**
   * Retrieves a single project owned by `userId`. Throws `NotFoundError` if missing.
   */
  public async findById(
    projectId: string,
    userId: string
  ): Promise<ProjectRecord> {
    const { data, error } = await this.db
      .from("projects")
      .select("*")
      .eq("id", projectId)
      .eq("user_id", userId)
      .maybeSingle();

    if (error) {
      throw new InternalServerError("Failed to query project", error.message);
    }
    if (!data) {
      throw new NotFoundError("Project", projectId);
    }

    return mapRowToProject(data);
  }

  /**
   * Retrieves a project by its per-user unique `slug`, or `null` if not found.
   */
  public async findBySlug(
    slug: string,
    userId: string
  ): Promise<ProjectRecord | null> {
    const { data, error } = await this.db
      .from("projects")
      .select("*")
      .eq("slug", slug)
      .eq("user_id", userId)
      .maybeSingle();

    if (error) {
      throw new InternalServerError(
        "Failed to query project by slug",
        error.message
      );
    }

    return data ? mapRowToProject(data) : null;
  }

  /**
   * Finds an existing project by slug derived from `name`, or creates it if absent.
   */
  public async findOrCreateByName(
    userId: string,
    name: string,
    defaults: Partial<
      Pick<ProjectInsert, "description" | "repository_url" | "primary_language">
    > = {}
  ): Promise<ProjectRecord> {
    const trimmedName = name.trim() || "Untitled Project";
    const slug = slugifyProjectName(trimmedName);

    const existing = await this.findBySlug(slug, userId);
    if (existing) {
      return existing;
    }

    return this.create({
      user_id: userId,
      name: trimmedName,
      slug,
      description: defaults.description ?? null,
      repository_url: defaults.repository_url ?? null,
      primary_language: defaults.primary_language ?? "typescript",
    });
  }

  /**
   * Lists projects for `userId` with optional status, risk level, search, sort,
   * and pagination filters.
   */
  public async listByUser(
    userId: string,
    params: ProjectListParams = {}
  ): Promise<{ items: ProjectRecord[]; total: number }> {
    const page = Math.max(1, params.page ?? 1);
    const pageSize = Math.min(100, Math.max(1, params.pageSize ?? 20));
    const from = (page - 1) * pageSize;
    const to = from + pageSize - 1;
    const sortBy = params.sortBy ?? "updated_at";
    const ascending = params.ascending ?? false;

    let query = this.db
      .from("projects")
      .select("*", { count: "exact" })
      .eq("user_id", userId);

    if (params.status !== undefined) {
      query = query.eq("status", params.status);
    }
    if (params.riskLevel !== undefined) {
      query = query.eq("risk_level", params.riskLevel);
    }
    if (params.search !== undefined && params.search.trim().length > 0) {
      const escaped = params.search.trim().replace(/[%_]/g, "\\$&");
      query = query.ilike("name", `%${escaped}%`);
    }

    const { data, error, count } = await query
      .order(sortBy, { ascending })
      .range(from, to);

    if (error) {
      throw new InternalServerError("Failed to list projects", error.message);
    }

    return {
      items: (data ?? []).map(mapRowToProject),
      total: count ?? 0,
    };
  }

  /**
   * Updates mutable fields on an owned project and returns the updated record.
   */
  public async update(
    projectId: string,
    userId: string,
    payload: ProjectUpdate
  ): Promise<ProjectRecord> {
    const { data, error } = await this.db
      .from("projects")
      .update(payload)
      .eq("id", projectId)
      .eq("user_id", userId)
      .select("*")
      .maybeSingle();

    if (error) {
      throw new InternalServerError("Failed to update project", error.message);
    }
    if (!data) {
      throw new NotFoundError("Project", projectId);
    }

    return mapRowToProject(data);
  }

  /**
   * Convenience method to update a project's latest security score and risk level.
   */
  public async updateSecuritySnapshot(
    projectId: string,
    userId: string,
    score: number,
    riskLevel: ProjectRiskLevel
  ): Promise<ProjectRecord> {
    const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
    return this.update(projectId, userId, {
      latest_security_score: clampedScore,
      risk_level: riskLevel,
    });
  }

  /**
   * Permanently deletes a project owned by `userId`. Throws `NotFoundError` if missing.
   */
  public async delete(projectId: string, userId: string): Promise<void> {
    const { data, error } = await this.db
      .from("projects")
      .delete()
      .eq("id", projectId)
      .eq("user_id", userId)
      .select("id")
      .maybeSingle();

    if (error) {
      throw new InternalServerError("Failed to delete project", error.message);
    }
    if (!data) {
      throw new NotFoundError("Project", projectId);
    }
  }
}
