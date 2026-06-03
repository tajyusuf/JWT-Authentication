import pytest


LOGIN = {
    "email": "user@example.com",
    "password": "correct-password",
    "device_id": "device-123",
}


@pytest.mark.asyncio
async def test_login_refresh_and_logout(client):
    login = await client.post("/api/v1/auth/login", json=LOGIN)
    assert login.status_code == 200
    first_tokens = login.json()
    assert first_tokens["access_token"]
    assert first_tokens["refresh_token"]

    refresh = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first_tokens["refresh_token"], "device_id": "device-123"},
    )
    assert refresh.status_code == 200
    second_tokens = refresh.json()
    assert second_tokens["refresh_token"] != first_tokens["refresh_token"]

    logout = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {second_tokens['access_token']}"},
        json={"refresh_token": second_tokens["refresh_token"], "device_id": "device-123"},
    )
    assert logout.status_code == 204

    sessions = await client.get(
        "/api/v1/auth/sessions",
        headers={"Authorization": f"Bearer {second_tokens['access_token']}"},
    )
    assert sessions.status_code == 401


@pytest.mark.asyncio
async def test_refresh_replay_marks_account_unavailable(client):
    login = await client.post("/api/v1/auth/login", json=LOGIN)
    old_refresh = login.json()["refresh_token"]

    rotated = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh, "device_id": "device-123"},
    )
    assert rotated.status_code == 200

    replay = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh, "device_id": "device-123"},
    )
    assert replay.status_code == 401
    assert replay.json()["detail"] == "Refresh token replay detected"

    login_again = await client.post("/api/v1/auth/login", json=LOGIN)
    assert login_again.status_code == 403


@pytest.mark.asyncio
async def test_rbac_admin_dependency(client):
    user_login = await client.post("/api/v1/auth/login", json=LOGIN)
    user_access = user_login.json()["access_token"]
    denied = await client.get("/api/v1/auth/admin/ping", headers={"Authorization": f"Bearer {user_access}"})
    assert denied.status_code == 403

    admin_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "correct-password", "device_id": "admin-device"},
    )
    admin_access = admin_login.json()["access_token"]
    allowed = await client.get("/api/v1/auth/admin/ping", headers={"Authorization": f"Bearer {admin_access}"})
    assert allowed.status_code == 200
