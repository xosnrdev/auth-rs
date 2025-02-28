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

| Method | Endpoint                   | Description                                 |
| ------ | -------------------------- | ------------------------------------------- |
| POST   | `/sessions/refresh-cookie` | Refresh tokens using a cookie.              |
| POST   | `/sessions/refresh`        | Refresh tokens using the request body.      |
| PATCH  | `/sessions/current`        | Revoke the current session.                 |
| PATCH  | `/sessions/:id`            | Revoke a specific session.                  |
| PATCH  | `/sessions`                | Revoke all sessions for the logged-in user. |

### Example Requests for Refresh Token

- **Using Refresh Token Cookie**

```bash
curl -X POST http://127.0.0.1:8080/sessions/refresh-cookie \
     --cookie "refreshToken=<REFRESH_TOKEN>"
```

- **Using Refresh Token in Request Body**

```bash
curl -X POST http://127.0.0.1:8080/sessions/refresh \
     -H "Content-Type: application/json" \
     -d '{"refreshToken": "<REFRESH_TOKEN>"}'
```

### Example Requests for Session Management

- **Revoke Current Session**

```bash
curl -X PATCH http://127.0.0.1:8080/sessions/current \
     -H "Authorization: Bearer <ACCESS_TOKEN>"
```

- **Revoke a Specific Session (Admin Only)**

```bash
curl -X PATCH http://127.0.0.1:8080/sessions/<USER_ID> \
     -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>"
```

- **Revoke All Sessions for all Logged-in Users (Admin Only)**

```bash
curl -X PATCH http://127.0.0.1:8080/sessions \
     -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>"
```
