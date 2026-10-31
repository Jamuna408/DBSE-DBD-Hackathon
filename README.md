# Campus Complaint Management

FastAPI + SQLAlchemy (SQLite) backend with a pastel single-page frontend.

## Run
    pip install -r requirements.txt
    uvicorn main:app --reload
Open http://127.0.0.1:8000  (API docs: /docs)

## Demo accounts
| Role    | Email               | Password   |
|---------|---------------------|------------|
| Student | student@campus.edu  | student123 |
| Faculty | faculty@campus.edu  | faculty123 |
| Admin   | admin@campus.edu    | admin123   |

## Roles
- Student: register complaints, track their own, see progress timeline.
- Faculty: file complaints; update and resolve the complaints assigned to them.
- Admin: dashboard, view all complaints, assign to faculty, change priority, close.

## Syllabus map
CO1: 3NF schema, FK/CHECK constraints, composite index, grouped SQL aggregates, status_history audit table
CO3: REST endpoints, Pydantic validation, dependency injection, JWT, RBAC, PBKDF2 hashing, OpenAPI at /docs
Python component: keyword classifier (`classify()` in main.py) and POST /api/classify
