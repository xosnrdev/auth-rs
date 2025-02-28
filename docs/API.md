# API Documentation

## Health Check

| Method | Endpoint | Description                    |
| ------ | -------- | ------------------------------ |
| GET    | `/`      | Verify the service is running. |

### Example Request

```bash
curl -X GET http://127.0.0.1:8080/
```

## User Management

| Method | Endpoint          | Description                                    |
| ------ | ----------------- | ---------------------------------------------- |
| POST   | `/users/register` | Register a new user.                           |
| GET    | `/users`          | Retrieve all users (admin only).               |
| GET    | `/users/me`       | Get the currently logged-in user's details.    |
| GET    | `/users/:id`      | Get a specific user's details (admin only).    |
| PATCH  | `/users/me`       | Update the logged-in user's details.           |
| PATCH  | `/users/:id`      | Update a specific user's details (admin only). |
| DELETE | `/users/me`       | Delete the logged-in user's account.           |
| DELETE | `/users/:id`      | Delete a specific user (admin only).           |

### Example Requests for User

- **Register a New User**

```bash
curl -X POST http://127.0.0.1:8080/users/register \
     -H "Content-Type: application/json" \
     -d '{"username": "user123", "email": "user123@example.com", "password": "password123"}'
```

- **Get Logged-in User Details**

```bash
curl -X GET http://127.0.0.1:8080/users/me \
     -H "Authorization: Bearer <ACCESS_TOKEN>"
```

- **Update Logged-in User Details**

```bash
curl -X PATCH http://127.0.0.1:8080/users/me \
     -H "Authorization: Bearer <ACCESS_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"email": "updated_email@example.com"}'
```

- **Delete Logged-in User**

```bash
curl -X DELETE http://127.0.0.1:8080/users/me \
     -H "Authorization: Bearer <ACCESS_TOKEN>"
```

### Example Requests for Admin

- **Retrieve All Users**

```bash
curl -X GET http://127.0.0.1:8080/users \
     -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>"
```

- **Get a Specific User's Details**

```bash
curl -X GET http://127.0.0.1:8080/users/<USER_ID> \
     -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>"
```

- **Update a Specific User's Details**

```bash
curl -X PATCH http://127.0.0.1:8080/users/<USER_ID> \
     -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"isAdmin": true}'
```

- **Delete a Specific User**

```bash
curl -X DELETE http://127.0.0.1:8080/users/<USER_ID> \
     -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>"
```

## Authentication

| Method | Endpoint       | Description                 |
| ------ | -------------- | --------------------------- |
| POST   | `/auth/login`  | Log in and receive tokens.  |
| POST   | `/auth/logout` | Log out the logged-in user. |

### Example Requests

- **Log In**

```bash
curl -X POST http://127.0.0.1:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "user123", "password": "password"}'
```

- **Log Out**

```bash
curl -X POST http://127.0.0.1:8080/auth/logout \
     -H "Authorization: Bearer <ACCESS_TOKEN>"
```

## Session Management

| Method | Endpoint           | Description                                          |
| ------ | ----------------- | ---------------------------------------------------- |
| GET    | `/sessions`       | List all sessions (admin only).                      |
| GET    | `/sessions/me`    | List sessions for the current user.                  |
| POST   | `/sessions/refresh-cookie` | Refresh tokens using a cookie.              |
| POST   | `/sessions/refresh`        | Refresh tokens using the request body.      |
| PATCH  | `/sessions/:id`   | Revoke a specific session (admin only).             |
| PATCH  | `/sessions`       | Revoke all sessions for all users (admin only).      |

### Example Requests for Session Management

- **List All Sessions (Admin Only)**

```bash
curl -X GET http://127.0.0.1:8080/sessions \
     -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>"
```

Response:
```json
{
  "sessions": [
    {
      "id": "0d056fed-cb49-485f-aff6-6975e86df7fb",
      "userId": "6960b991-4cb0-4960-bcaa-d52d7ca7b395",
      "isRevoked": false,
      "expiresAt": "2025-03-01T22:48:41.133705Z",
      "createdAt": "2025-02-28T22:48:41.133705Z"
    }
  ]
}
```

- **List Current User's Sessions**

```bash
curl -X GET http://127.0.0.1:8080/sessions/me \
     -H "Authorization: Bearer <ACCESS_TOKEN>"
```

Response:
```json
{
  "sessions": [
    {
      "id": "0d056fed-cb49-485f-aff6-6975e86df7fb",
      "userId": "6960b991-4cb0-4960-bcaa-d52d7ca7b395",
      "isRevoked": false,
      "expiresAt": "2025-03-01T22:48:41.133705Z",
      "createdAt": "2025-02-28T22:48:41.133705Z"
    }
  ]
}
```

- **Revoke a Specific Session (Admin Only)**

```bash
curl -X PATCH http://127.0.0.1:8080/sessions/<SESSION_ID> \
     -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>"
```

Response: 204 No Content

- **Revoke All Sessions (Admin Only)**

```bash
curl -X PATCH http://127.0.0.1:8080/sessions \
     -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>"
```

Response: 204 No Content

### Example Requests for Token Refresh

- **Using Refresh Token Cookie**

```bash
curl -X POST http://127.0.0.1:8080/sessions/refresh-cookie \
     --cookie "refreshToken=<REFRESH_TOKEN>"
```

Response:
```json
{
  "accessToken": "<NEW_ACCESS_TOKEN>"
}
```

- **Using Refresh Token in Request Body**

```bash
curl -X POST http://127.0.0.1:8080/sessions/refresh \
     -H "Content-Type: application/json" \
     -d '{"refreshToken": "<REFRESH_TOKEN>"}'
```

Response:
```json
{
  "accessToken": "<NEW_ACCESS_TOKEN>"
}
```

### Error Responses

- **401 Unauthorized**
```json
{
  "message": "Admin session has been revoked or expired",
  "status": 401
}
```

- **403 Forbidden**
```json
{
  "message": "Access denied: admin privileges required",
  "status": 403
}
```

- **404 Not Found**
```json
{
  "message": "Session not found",
  "status": 404
}
```

- **409 Conflict**
```json
{
  "message": "Session {id} is already revoked",
  "status": 409
}
```

- **410 Gone**
```json
{
  "message": "Session {id} has expired",
  "status": 410
}
```

### Implementation Notes

1. **Session Uniqueness**: The system enforces a single active session per user. When logging in:
   - If an active session exists, it will be reused
   - If the existing session is expired or revoked, it will be deleted and a new one created

2. **Token Types**:
   - Access Token: Short-lived token for API access
   - Refresh Token: Long-lived token stored in HTTP-only cookies and database

3. **Security Measures**:
   - Refresh tokens are stored in HTTP-only, secure cookies with strict same-site policy
   - Session revocation is permanent and cannot be undone
   - Admin users can manage other sessions while their own session remains valid
