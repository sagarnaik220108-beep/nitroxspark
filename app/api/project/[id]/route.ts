import { withAuth } from "@/lib/auth/middleware";
import { projectService } from "@/services/project.service";
import { apiSuccess, ValidationError } from "@/utils";

/**
 * GET /api/project/[id]
 * Retrieves a single project owned by the authenticated user.
 */
export const GET = withAuth<{ id: string }>(async (_request, auth, context) => {
  const { id } = await context.params;
  const project = await projectService.getProjectById(id, auth);

  return apiSuccess(project, 200, undefined, {
    "Cache-Control": "no-store",
  });
});

/**
 * PUT /api/project/[id]
 * Updates an existing project owned by the authenticated user.
 */
export const PUT = withAuth<{ id: string }>(async (request, auth, context) => {
  const { id } = await context.params;

  let rawBody: unknown;
  try {
    rawBody = await request.json();
  } catch {
    throw new ValidationError("Request body must be valid JSON");
  }

  const updatedProject = await projectService.updateProject(id, rawBody, auth);

  return apiSuccess(updatedProject, 200, undefined, {
    "Cache-Control": "no-store",
  });
});

/**
 * DELETE /api/project/[id]
 * Deletes a project owned by the authenticated user.
 */
export const DELETE = withAuth<{ id: string }>(
  async (_request, auth, context) => {
    const { id } = await context.params;
    const result = await projectService.deleteProject(id, auth);

    return apiSuccess(result, 200, undefined, {
      "Cache-Control": "no-store",
    });
  }
);
