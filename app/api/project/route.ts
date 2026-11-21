import { withAuth } from "@/lib/auth/middleware";
import { projectService } from "@/services/project.service";
import { apiSuccess, ValidationError } from "@/utils";

function readOptionalParam(
  searchParams: URLSearchParams,
  key: string
): string | undefined {
  const value = searchParams.get(key);
  if (value === null) return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * GET /api/project
 * Returns a paginated list of the authenticated user's projects.
 * Query parameters: `page`, `pageSize`, `status`, `environment`, `search`.
 */
export const GET = withAuth(async (request, auth) => {
  const { searchParams } = request.nextUrl;

  const rawQuery = {
    page: readOptionalParam(searchParams, "page"),
    pageSize: readOptionalParam(searchParams, "pageSize"),
    status: readOptionalParam(searchParams, "status"),
    environment: readOptionalParam(searchParams, "environment"),
    search: readOptionalParam(searchParams, "search"),
  };

  const { projects, pagination } = await projectService.listProjects(
    rawQuery,
    auth
  );

  return apiSuccess({ projects }, 200, pagination, {
    "Cache-Control": "no-store",
  });
});

/**
 * POST /api/project
 * Creates a new project for the authenticated user and returns 201 Created.
 */
export const POST = withAuth(async (request, auth) => {
  let rawBody: unknown;
  try {
    rawBody = await request.json();
  } catch {
    throw new ValidationError("Request body must be valid JSON");
  }

  const project = await projectService.createProject(rawBody, auth);

  return apiSuccess(project, 201, undefined, {
    "Cache-Control": "no-store",
  });
});
