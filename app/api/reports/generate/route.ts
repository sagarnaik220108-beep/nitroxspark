import { NextResponse } from "next/server";
import { reportGeneratorService } from "@/services/report-generator.service";
import { apiSuccess, handleRouteError, ValidationError } from "@/utils";

/**
 * POST /api/reports/generate
 * Generates a modular Sentinel AI Security Report in JSON, HTML, PDF-Ready AST,
 * or all three formats simultaneously.
 *
 * When `format === "html"` and `download === true`, returns the raw self-contained
 * HTML5 document with `Content-Disposition: attachment` for direct download.
 */
export async function POST(request: Request) {
  try {
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      throw new ValidationError("Request body must be valid JSON");
    }

    const { format, download, bundle } =
      reportGeneratorService.generateFromRequest(rawBody);

    if (format === "html" && download && bundle.html) {
      return new NextResponse(bundle.html.content, {
        status: 200,
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Content-Disposition": bundle.html.exportMetadata.contentDisposition,
          "X-Content-Type-Options": "nosniff",
          "Cache-Control": "no-store",
        },
      });
    }

    return apiSuccess(
      {
        format,
        reportId: bundle.reportId,
        generatedAt: bundle.generatedAt,
        report: bundle.canonical,
        ...(bundle.json ? { json: bundle.json } : {}),
        ...(bundle.html ? { html: bundle.html } : {}),
        ...(bundle.pdfReady ? { pdfReady: bundle.pdfReady } : {}),
        exportMetadata: bundle.exportMetadata,
      },
      200
    );
  } catch (error) {
    return handleRouteError(error);
  }
}
