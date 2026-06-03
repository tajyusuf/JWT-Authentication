from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import settings
from app.middleware.rate_limit import RateLimitMiddleware


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Authentication and authorization microservice with JWT, RTR, RBAC, sessions, and audit logging.",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    app.add_middleware(RateLimitMiddleware)
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()

