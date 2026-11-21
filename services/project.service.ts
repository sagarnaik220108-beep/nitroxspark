import type { SupabaseClient } from "@supabase/supabase-js";
import { z } from "zod";
import type { PaginationMeta, SupportedLanguage } from "@/types";
import { AuditRepository } from "@/database/repositories";
import {
  authService,
  type AuthenticatedContext,
  type SupabaseServerClient,
} from "@/services/auth.service";
import {
  ConflictError,
  InternalServerError,
  NotFoundError,
  parseOrThrow,
  supportedLanguageSchema,
  uuidParamSchema,
} from "@/utils";

export const PROJECT_ENVIRONMENTS = [
  "development",
  "staging",
  "production",
] as const;

export type ProjectEnvironment = (typeof PROJECT_ENVIRONMENTS)[number];

export const PROJECT_STATUSES = ["active", "archived"] as const;

export type ProjectStatus = (typeof PROJECT_STATUSES)[number];

export type ProjectRow = {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  repository_url: string | null;
  default_language: SupportedLanguage;
  environment: ProjectEnvironment;
  status: ProjectStatus;
  created_at: string;
  updated_at: string;
};

export type ProjectInsert = {
  id?: string;
  user_id: string;
  name: string;
  description?: string | null;
  repository_url?: string | null;
  default_language?: SupportedLanguage;
  environment?: ProjectEnvironment;
  status?: ProjectStatus;
  created_at?: string;
  updated_at?: string;
};

export type ProjectUpdate = {
  name?: string;
  description?: string | null;
  repository_url?: string | null;
  default_language?: SupportedLanguage;
  environment?: ProjectEnvironment;
  status?: ProjectStatus;
  updated_at?: string;
};

/**
 * Self-contained typed schema view for `public.projects` so ProjectService
 * remains strictly typed against Supabase without depending on shared schema edits.
 */
interface ProjectsTableSchema {
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

export interface Project {
  id: string;
  userId: string;
  name: string;
  description: string | null;
  repositoryUrl: string | null;
  defaultLanguage: SupportedLanguage;
  environment: ProjectEnvironment;
  status: ProjectStatus;
  createdAt: string;
  updatedAt: string;
}

export const projectEnvironmentSchema = z.enum(PROJECT_ENVIRONMENTS);
export const projectStatusSchema = z.enum(PROJECT_STATUSES);

export const createProjectSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, "Project name is required")
    .max(120, "Project name must be 120 characters or fewer"),
  description: z
    .string()
    .trim()
    .max(1000, "Description must be 1000 characters or fewer")
    .nullable()
    .optional(),
  repositoryUrl: z
    .string()
    .trim()
    .url("repositoryUrl must be a valid URL")
    .max(500, "repositoryUrl must be 500 characters or fewer")
    .nullable()
    .optional(),
  defaultLanguage: supportedLanguageSchema.default("typescript"),
  environment: projectEnvironmentSchema.default("development"),
});

export type CreateProjectInput = z.infer<typeof createProjectSchema>;

export const updateProjectSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(1, "Project name cannot be empty")
      .max(120, "Project name must be 120 characters or fewer")
      .optional(),
    description: z
      .string()
      .trim()
      .max(1000, "Description must be 1000 characters or fewer")
      .nullable()
      .optional(),
    repositoryUrl: z
      .string()
      .trim()
      .url("repositoryUrl must be a valid URL")
      .max(500, "repositoryUrl must be 500 characters or fewer")
      .nullable()
      .optional(),
    defaultLanguage: supportedLanguageSchema.optional(),
    environment: projectEnvironmentSchema.optional(),
    status: projectStatusSchema.optional(),
  })
  .refine(
    (data) =>
      data.name !== undefined ||
      data.description !== undefined ||
      data.repositoryUrl !== undefined ||
      data.defaultLanguage !== undefined ||
      data.environment !== undefined ||
      data.status !== undefined,
    {
      message: "At least one updatable field must be provided",
    }
  );

export type UpdateProjectInput = z.infer<typeof updateProjectSchema>;

export const listProjectsQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  status: projectStatusSchema.optional(),
  environment: projectEnvironmentSchema.optional(),
  search: z.string().trim().min(1).max(120).optional(),
});

export type ListProjectsQuery = z.infer<typeof listProjectsQuerySchema>;

function getProjectsClient(
  supabase: SupabaseServerClient
): SupabaseClient<ProjectsTableSchema> {
  return supabase as unknown as SupabaseClient<ProjectsTableSchema>;
}

function mapRowToProject(row: ProjectRow): Project {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    description: row.description,
    repositoryUrl: row.repository_url,
    defaultLanguage: row.default_language,
    environment: row.environment,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * ProjectService manages CRUD operations for Sentinel AI user projects
 * with strict Zod validation, ownership scoping, and audit logging.
 */
export class ProjectService {
  private async resolveContext(
    context?: AuthenticatedContext
  ): Promise<AuthenticatedContext> {
    if (context) {
      return context;
    }
    return authService.requireAuthenticatedUser();
  }

  public async createProject(
    rawInput: unknown,
    context?: AuthenticatedContext
  ): Promise<Project> {
    const input = parseOrThrow(createProjectSchema, rawInput);
    const { user, supabase } = await this.resolveContext(context);
    const projectsClient = getProjectsClient(supabase);
    const auditRepo = new AuditRepository(supabase);

    const description =
      input.description !== undefined &&
      input.description !== null &&
      input.description.length > 0
        ? input.description
        : null;

    const { data, error } = await projectsClient
      .from("projects")
      .insert({
        user_id: user.id,
        name: input.name,
        description,
        repository_url: input.repositoryUrl ?? null,
        default_language: input.defaultLanguage,
        environment: input.environment,
        status: "active",
      })
      .select("*")
      .single();

    if (error) {
      if (error.code === "23505") {
        throw new ConflictError(
          `A project named '${input.name}' already exists`
        );
      }
      throw new InternalServerError(
        "Failed to create project",
        error.message
      );
    }

    if (!data) {
      throw new InternalServerError("Failed to create project");
    }

    await auditRepo.record({
      userId: user.id,
      action: "project.created",
      resourceType: "project",
      resourceId: data.id,
      metadata: {
        name: data.name,
        environment: data.environment,
        defaultLanguage: data.default_language,
      },
    });

    return mapRowToProject(data);
  }

  public async listProjects(
    rawQuery: unknown = {},
    context?: AuthenticatedContext
  ): Promise<{
    projects: Project[];
    pagination: PaginationMeta;
  }> {
    const { page, pageSize, status, environment, search } = parseOrThrow(
      listProjectsQuerySchema,
      rawQuery
    );
    const { user, supabase } = await this.resolveContext(context);
    const projectsClient = getProjectsClient(supabase);

    const from = (page - 1) * pageSize;
    const to = from + pageSize - 1;

    let query = projectsClient
      .from("projects")
      .select("*", { count: "exact" })
      .eq("user_id", user.id);

    if (status !== undefined) {
      query = query.eq("status", status);
    }
    if (environment !== undefined) {
      query = query.eq("environment", environment);
    }
    if (search !== undefined) {
      query = query.ilike("name", `%${search}%`);
    }

    const { data, error, count } = await query
      .order("updated_at", { ascending: false })
      .range(from, to);

    if (error) {
      throw new InternalServerError("Failed to list projects", error.message);
    }

    const total = count ?? 0;

    return {
      projects: (data ?? []).map(mapRowToProject),
      pagination: {
        page,
        pageSize,
        total,
        totalPages: Math.max(1, Math.ceil(total / pageSize)),
      },
    };
  }

  public async getProjectById(
    projectId: string,
    context?: AuthenticatedContext
  ): Promise<Project> {
    const validId = parseOrThrow(uuidParamSchema, projectId);
    const { user, supabase } = await this.resolveContext(context);
    const projectsClient = getProjectsClient(supabase);

    const { data, error } = await projectsClient
      .from("projects")
      .select("*")
      .eq("id", validId)
      .eq("user_id", user.id)
      .maybeSingle();

    if (error) {
      throw new InternalServerError("Failed to fetch project", error.message);
    }
    if (!data) {
      throw new NotFoundError("Project", validId);
    }

    return mapRowToProject(data);
  }

  public async updateProject(
    projectId: string,
    rawInput: unknown,
    context?: AuthenticatedContext
  ): Promise<Project> {
    const validId = parseOrThrow(uuidParamSchema, projectId);
    const input = parseOrThrow(updateProjectSchema, rawInput);
    const { user, supabase } = await this.resolveContext(context);
    const projectsClient = getProjectsClient(supabase);
    const auditRepo = new AuditRepository(supabase);

    const updatePayload: ProjectUpdate = {
      updated_at: new Date().toISOString(),
    };

    if (input.name !== undefined) {
      updatePayload.name = input.name;
    }
    if (input.description !== undefined) {
      updatePayload.description =
        input.description !== null && input.description.length > 0
          ? input.description
          : null;
    }
    if (input.repositoryUrl !== undefined) {
      updatePayload.repository_url = input.repositoryUrl;
    }
    if (input.defaultLanguage !== undefined) {
      updatePayload.default_language = input.defaultLanguage;
    }
    if (input.environment !== undefined) {
      updatePayload.environment = input.environment;
    }
    if (input.status !== undefined) {
      updatePayload.status = input.status;
    }

    const { data, error } = await projectsClient
      .from("projects")
      .update(updatePayload)
      .eq("id", validId)
      .eq("user_id", user.id)
      .select("*")
      .maybeSingle();

    if (error) {
      if (error.code === "23505") {
        throw new ConflictError(
          `A project named '${input.name ?? ""}' already exists`
        );
      }
      throw new InternalServerError("Failed to update project", error.message);
    }

    if (!data) {
      throw new NotFoundError("Project", validId);
    }

    await auditRepo.record({
      userId: user.id,
      action: "project.updated",
      resourceType: "project",
      resourceId: data.id,
      metadata: {
        updatedFields: Object.keys(input),
      },
    });

    return mapRowToProject(data);
  }

  public async deleteProject(
    projectId: string,
    context?: AuthenticatedContext
  ): Promise<{ deletedId: string }> {
    const validId = parseOrThrow(uuidParamSchema, projectId);
    const { user, supabase } = await this.resolveContext(context);
    const projectsClient = getProjectsClient(supabase);
    const auditRepo = new AuditRepository(supabase);

    const { data, error } = await projectsClient
      .from("projects")
      .delete()
      .eq("id", validId)
      .eq("user_id", user.id)
      .select("id")
      .maybeSingle();

    if (error) {
      throw new InternalServerError("Failed to delete project", error.message);
    }
    if (!data) {
      throw new NotFoundError("Project", validId);
    }

    await auditRepo.record({
      userId: user.id,
      action: "project.deleted",
      resourceType: "project",
      resourceId: validId,
    });

    return { deletedId: validId };
  }
}

export const projectService = new ProjectService();
