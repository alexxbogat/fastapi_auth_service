# FastAPI Auth Service

---

## Environment Variables

Create a `.env` file in the project root with the following settings:

```ini
# Security
SECRET_KEY=your_secret_key_here
ALGORITHM='HS256'
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_MINUTES=10080
EMAIL_TOKEN_EXPIRE_MINUTES=1440

# Database
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASS=your_db_pass
DB_HOST=db_host
DB_PORT=db_port

DATABASE_URL='your_db_url'

# Redis
REDIS_URL='redis://localhost:6379'

# Email
EMAIL_HOST='smtp.gmail.com'
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your_email
EMAIL_HOST_PASSWORD=your_smtp_pass
```
---

## API Endpoints

### Auth Routes

- `POST /register` — Register a new user  
- `GET /verify?token=<token>` — Verify email address  
- `POST /login` — Login user and receive JWT tokens  
- `POST /logout` — Logout user and revoke tokens  
- `POST /token/refresh-token` — Refresh JWT tokens

### User Routes

- `POST /user/change-password` — Change current user password  
- `PUT /user/update` — Update current user profile  
- `PUT /user/delete` — Soft-delete current user profile  
- `PUT /user/balance` — Withdraw money from the current user's balance 
- `GET /user/balance` — Get current user balance
- `GET /user` — Get current user profile

### Admin Routes

- `PUT /admin/user/block-status` — Block or unblock a user  
- `GET /admin/user/delete-status` — Get all soft-deleted users  
- `GET /admin/all-users` — List all users with filters and sorting  

---

## Notes

- Use the `.env` file to configure your environment.  
- Admin users cannot delete their own accounts.  
- Users with a positive balance cannot switch to admin role.  
- Access tokens are short-lived; refresh tokens last longer for session continuation.  
- Soft-deleted users (`is_deleted=True`) are excluded from normal queries.
