/**
 * Structured application error hierarchy for Sentinel AI.
 * Services and repositories throw typed errors; API routes and Server Actions
 * translate them into standardized JSON error envelopes.
 */

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly details?: unknown;
  public readonly isOperational: boolean;

  constructor(
    message: string,
    statusCode = 500,
    code = "INTERNAL_SERVER_ERROR",
    details?: unknown,
    isOperational = true
  ) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = isOperational;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

export class ValidationError extends AppError {
  constructor(message = "Invalid request payload", details?: unknown) {
    super(message, 400, "VALIDATION_ERROR", details);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = "Authentication required") {
    super(message, 401, "UNAUTHORIZED");
  }
}

export class ForbiddenError extends AppError {
  constructor(message = "You do not have permission to perform this action") {
    super(message, 403, "FORBIDDEN");
  }
}

export class NotFoundError extends AppError {
  constructor(resource = "Resource", id?: string) {
    const message = id
      ? `${resource} with id '${id}' was not found`
      : `${resource} was not found`;
    super(message, 404, "NOT_FOUND");
  }
}

export class ConflictError extends AppError {
  constructor(message = "Resource already exists", details?: unknown) {
    super(message, 409, "CONFLICT", details);
  }
}

export class RateLimitError extends AppError {
  constructor(
    message = "Too many requests. Please slow down and try again.",
    retryAfterSeconds?: number
  ) {
    super(
      message,
      429,
      "RATE_LIMIT_EXCEEDED",
      retryAfterSeconds ? { retryAfterSeconds } : undefined
    );
  }
}

export class InternalServerError extends AppError {
  constructor(message = "An unexpected internal error occurred", details?: unknown) {
    super(message, 500, "INTERNAL_SERVER_ERROR", details, false);
  }
}
