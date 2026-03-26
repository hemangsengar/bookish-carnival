from fastapi import Header, HTTPException, status

from app.core.config import settings


def require_service_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if x_api_key != settings.service_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )


def require_roles(*allowed_roles: str):
    normalized_allowed = {role.lower() for role in allowed_roles}

    def _require_role(x_user_role: str | None = Header(default=None)) -> str:
        if not x_user_role:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing x-user-role header",
            )

        normalized_role = x_user_role.lower()
        if normalized_role not in normalized_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )

        return normalized_role

    return _require_role
