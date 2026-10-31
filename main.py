"""Campus Complaint Management: FastAPI backend (layered in one file for speed).
Roles: student, faculty, admin.  Run: uvicorn main:app --reload
"""
import hashlib, hmac, os, secrets, datetime as dt
from typing import Optional, Literal

import jwt
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import (create_engine, Integer, String, Text, DateTime, ForeignKey,
                        CheckConstraint, Index, func, select)
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column, relationship,
                            sessionmaker, Session)

# ---------------------------------------------------------------- config
SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
ALGO = "HS256"
engine = create_engine("sqlite:///./complaints.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

STATUSES = ["Open", "Assigned", "In Progress", "Resolved", "Closed"]
PRIORITIES = ["Low", "Medium", "High", "Critical"]
CATEGORIES = ["Electrical", "Plumbing", "Internet & IT", "Classroom & Furniture",
              "Cleanliness", "Security & Safety", "Transport", "Canteen & Food", "Other"]


def now():
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------- models (3NF)
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    email: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(10))
    __table_args__ = (CheckConstraint("role in ('student','faculty','admin')", name="ck_role"),)


class Complaint(Base):
    __tablename__ = "complaints"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(150))
    description: Mapped[str] = mapped_column(Text)
    location: Mapped[str] = mapped_column(String(120), default="")
    category: Mapped[str] = mapped_column(String(40))
    priority: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(15), default="Open")
    resolution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    assigned_to: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    resolved_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    creator: Mapped[User] = relationship(foreign_keys=[created_by])
    assignee: Mapped[Optional[User]] = relationship(foreign_keys=[assigned_to])
    history: Mapped[list["StatusHistory"]] = relationship(order_by="StatusHistory.id",
                                                          cascade="all, delete-orphan")
    __table_args__ = (
        CheckConstraint("priority in ('Low','Medium','High','Critical')", name="ck_priority"),
        Index("ix_complaint_status_priority", "status", "priority"),
    )


class StatusHistory(Base):
    __tablename__ = "status_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    complaint_id: Mapped[int] = mapped_column(ForeignKey("complaints.id"), index=True)
    status: Mapped[str] = mapped_column(String(15))
    note: Mapped[str] = mapped_column(String(300), default="")
    changed_by: Mapped[str] = mapped_column(String(80))
    changed_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)


# ---------------------------------------------------------------- security
def hash_pw(pw: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${h}"


def check_pw(pw: str, stored: str) -> bool:
    salt, _ = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, salt), stored)


def make_token(u: User) -> str:
    exp = now() + dt.timedelta(hours=8)
    return jwt.encode({"sub": str(u.id), "role": u.role, "exp": exp}, SECRET, ALGO)


bearer = HTTPBearer(auto_error=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer),
                 db: Session = Depends(get_db)) -> User:
    if not cred:
        raise HTTPException(401, "Please sign in")
    try:
        data = jwt.decode(cred.credentials, SECRET, algorithms=[ALGO])
    except jwt.PyJWTError:
        raise HTTPException(401, "Session expired, please sign in again")
    user = db.get(User, int(data["sub"]))
    if not user:
        raise HTTPException(401, "Unknown user")
    return user


def require(*roles):  # RBAC dependency
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "You do not have access to this action")
        return user
    return dep


# ---------------------------------------------------------------- classifier
KEYWORDS = {
    "Electrical": ["light", "fan", "switch", "socket", "power", "electric", "wire", "tube", "bulb", "ac ", "projector"],
    "Plumbing": ["water", "tap", "leak", "pipe", "toilet", "washroom", "drain", "flush", "geyser", "overflow"],
    "Internet & IT": ["wifi", "wi-fi", "internet", "network", "lab computer", "computer", "server", "lan", "portal", "login"],
    "Classroom & Furniture": ["bench", "desk", "chair", "board", "classroom", "window", "door", "furniture", "broken"],
    "Cleanliness": ["dirty", "garbage", "dustbin", "clean", "smell", "waste", "sweep", "mosquito", "pest"],
    "Security & Safety": ["theft", "stolen", "fire", "unsafe", "security", "cctv", "harass", "fight", "gate", "lock"],
    "Transport": ["bus", "transport", "driver", "route", "parking"],
    "Canteen & Food": ["canteen", "food", "mess", "meal", "hygiene", "lunch", "tea"],
}
URGENT = {
    "Critical": ["fire", "short circuit", "sparks", "electric shock", "gas leak", "harass", "injur", "collapse", "flood"],
    "High": ["no water", "no power", "power cut", "not working", "stolen", "theft", "leak", "unsafe", "exam", "urgent", "overflow"],
    "Medium": ["slow", "broken", "dirty", "noise", "flicker", "delay"],
}


def classify(text: str) -> dict:
    t = " " + text.lower() + " "
    scores = {c: sum(t.count(k) for k in kws) for c, kws in KEYWORDS.items()}
    best = max(scores, key=scores.get)
    category = best if scores[best] > 0 else "Other"
    priority = "Low"
    for level in ("Critical", "High", "Medium"):
        if any(k in t for k in URGENT[level]):
            priority = level
            break
    if category == "Security & Safety" and priority in ("Low", "Medium"):
        priority = "High"
    return {"category": category, "priority": priority}


# ---------------------------------------------------------------- schemas
class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: str = Field(min_length=5, max_length=120)
    password: str = Field(min_length=6, max_length=100)
    role: Literal["student", "faculty"]


class LoginIn(BaseModel):
    email: str
    password: str


class ClassifyIn(BaseModel):
    title: str = ""
    description: str = ""


class ComplaintIn(BaseModel):
    title: str = Field(min_length=4, max_length=150)
    description: str = Field(min_length=10)
    location: str = ""
    category: Optional[str] = None
    priority: Optional[str] = None


class AssignIn(BaseModel):
    assignee_id: int
    priority: Optional[Literal["Low", "Medium", "High", "Critical"]] = None


class StatusIn(BaseModel):
    status: Literal["Open", "Assigned", "In Progress", "Resolved", "Closed"]
    note: str = ""


class ResolveIn(BaseModel):
    resolution: str = Field(min_length=5)


def out(c: Complaint, detail=False) -> dict:
    d = {
        "id": c.id, "title": c.title, "description": c.description, "location": c.location,
        "category": c.category, "priority": c.priority, "status": c.status,
        "resolution": c.resolution, "created_at": c.created_at.isoformat(),
        "resolved_at": c.resolved_at.isoformat() if c.resolved_at else None,
        "created_by": c.creator.name, "created_by_role": c.creator.role,
        "assigned_to": c.assignee.name if c.assignee else None, "assigned_to_id": c.assigned_to,
    }
    if detail:
        d["history"] = [{"status": h.status, "note": h.note, "by": h.changed_by,
                         "at": h.changed_at.isoformat()} for h in c.history]
    return d


def log(c: Complaint, status: str, note: str, who: User):
    c.history.append(StatusHistory(status=status, note=note, changed_by=f"{who.name} ({who.role})"))


def can_view(u: User, c: Complaint) -> bool:
    return u.role == "admin" or c.created_by == u.id or c.assigned_to == u.id


# ---------------------------------------------------------------- app
app = FastAPI(title="Campus Complaint Management", version="1.0")


@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if not db.scalar(select(func.count(User.id))):
            demo = [("Admin", "admin@campus.edu", "admin123", "admin"),
                    ("Prof. Rao", "faculty@campus.edu", "faculty123", "faculty"),
                    ("Prof. Meera", "meera@campus.edu", "faculty123", "faculty"),
                    ("Asha Student", "student@campus.edu", "student123", "student")]
            for n, e, p, r in demo:
                db.add(User(name=n, email=e, password_hash=hash_pw(p), role=r))
            db.flush()
            student = db.scalar(select(User).where(User.role == "student"))
            for t, d, loc in [
                ("Water leaking in Hostel B washroom", "The tap is leaking and water is overflowing since morning.", "Hostel B, Floor 2"),
                ("Wi-Fi very slow in library", "Internet is slow in the library reading hall during the day.", "Library"),
                ("Projector not working in Room 204", "The projector shows no display before the exam lecture.", "Block A, Room 204"),
            ]:
                cl = classify(t + " " + d)
                c = Complaint(title=t, description=d, location=loc, created_by=student.id, **cl)
                log(c, "Open", "Complaint registered", student)
                db.add(c)
            db.commit()


@app.post("/api/register", status_code=201)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "That email is already registered")
    u = User(name=body.name.strip(), email=email, password_hash=hash_pw(body.password), role=body.role)
    db.add(u); db.commit()
    return {"token": make_token(u), "user": {"id": u.id, "name": u.name, "role": u.role}}


@app.post("/api/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    u = db.scalar(select(User).where(User.email == body.email.strip().lower()))
    if not u or not check_pw(body.password, u.password_hash):
        raise HTTPException(401, "Email or password is incorrect")
    return {"token": make_token(u), "user": {"id": u.id, "name": u.name, "role": u.role}}


@app.get("/api/me")
def me(u: User = Depends(current_user)):
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role}


@app.get("/api/meta")
def meta():
    return {"statuses": STATUSES, "priorities": PRIORITIES, "categories": CATEGORIES}


@app.post("/api/classify")
def classify_ep(body: ClassifyIn, _: User = Depends(current_user)):
    return classify(body.title + " " + body.description)


@app.post("/api/complaints", status_code=201)
def create(body: ComplaintIn, u: User = Depends(require("student", "faculty")), db: Session = Depends(get_db)):
    suggestion = classify(body.title + " " + body.description)
    category = body.category if body.category in CATEGORIES else suggestion["category"]
    priority = body.priority if body.priority in PRIORITIES else suggestion["priority"]
    c = Complaint(title=body.title.strip(), description=body.description.strip(), location=body.location.strip(),
                  category=category, priority=priority, created_by=u.id)
    log(c, "Open", "Complaint registered", u)
    db.add(c); db.commit()
    return out(c, True)


@app.get("/api/complaints")
def list_complaints(status: Optional[str] = None, priority: Optional[str] = None,
                    category: Optional[str] = None, scope: str = "mine",
                    u: User = Depends(current_user), db: Session = Depends(get_db)):
    q = select(Complaint).order_by(Complaint.id.desc())
    if u.role == "student":
        q = q.where(Complaint.created_by == u.id)
    elif u.role == "faculty":
        q = q.where((Complaint.assigned_to == u.id) if scope == "assigned" else (Complaint.created_by == u.id))
    if status: q = q.where(Complaint.status == status)
    if priority: q = q.where(Complaint.priority == priority)
    if category: q = q.where(Complaint.category == category)
    return [out(c) for c in db.scalars(q)]


@app.get("/api/complaints/{cid}")
def get_one(cid: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    c = db.get(Complaint, cid)
    if not c or not can_view(u, c):
        raise HTTPException(404, "Complaint not found")
    return out(c, True)


@app.patch("/api/complaints/{cid}/assign")
def assign(cid: int, body: AssignIn, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    c = db.get(Complaint, cid)
    f = db.get(User, body.assignee_id)
    if not c: raise HTTPException(404, "Complaint not found")
    if not f or f.role != "faculty": raise HTTPException(400, "Assignee must be a faculty member")
    c.assigned_to = f.id
    if body.priority: c.priority = body.priority
    if c.status == "Open": c.status = "Assigned"
    log(c, c.status, f"Assigned to {f.name}" + (f", priority {c.priority}" if body.priority else ""), u)
    db.commit()
    return out(c, True)


@app.patch("/api/complaints/{cid}/status")
def set_status(cid: int, body: StatusIn, u: User = Depends(require("admin", "faculty")), db: Session = Depends(get_db)):
    c = db.get(Complaint, cid)
    if not c: raise HTTPException(404, "Complaint not found")
    if u.role == "faculty" and c.assigned_to != u.id:
        raise HTTPException(403, "Only the assigned faculty member can update this complaint")
    if body.status == "Closed" and u.role != "admin":
        raise HTTPException(403, "Only admin can close a complaint")
    c.status = body.status
    log(c, body.status, body.note or "Status updated", u)
    db.commit()
    return out(c, True)


@app.post("/api/complaints/{cid}/resolve")
def resolve(cid: int, body: ResolveIn, u: User = Depends(require("admin", "faculty")), db: Session = Depends(get_db)):
    c = db.get(Complaint, cid)
    if not c: raise HTTPException(404, "Complaint not found")
    if u.role == "faculty" and c.assigned_to != u.id:
        raise HTTPException(403, "Only the assigned faculty member can resolve this complaint")
    c.status, c.resolution, c.resolved_at = "Resolved", body.resolution, now()
    log(c, "Resolved", body.resolution, u)
    db.commit()
    return out(c, True)


@app.get("/api/users")
def users(role: Optional[str] = None, _: User = Depends(require("admin")), db: Session = Depends(get_db)):
    q = select(User).order_by(User.name)
    if role: q = q.where(User.role == role)
    return [{"id": x.id, "name": x.name, "email": x.email, "role": x.role} for x in db.scalars(q)]


@app.get("/api/stats")
def stats(_: User = Depends(require("admin")), db: Session = Depends(get_db)):
    def group(col):
        return {k: v for k, v in db.execute(select(col, func.count(Complaint.id)).group_by(col))}
    total = db.scalar(select(func.count(Complaint.id)))
    # average resolution time in hours
    rows = db.execute(select(Complaint.created_at, Complaint.resolved_at).where(Complaint.resolved_at.is_not(None))).all()
    avg = round(sum((r - c).total_seconds() for c, r in rows) / len(rows) / 3600, 1) if rows else None
    # workload per faculty (window-style ranking done in SQL via group + order)
    load = db.execute(select(User.name, func.count(Complaint.id)).join(Complaint, Complaint.assigned_to == User.id)
                      .where(Complaint.status.in_(["Assigned", "In Progress"])).group_by(User.id)
                      .order_by(func.count(Complaint.id).desc())).all()
    return {"total": total, "by_status": group(Complaint.status), "by_priority": group(Complaint.priority),
            "by_category": group(Complaint.category), "avg_resolution_hours": avg,
            "faculty_load": [{"name": n, "open": c} for n, c in load]}


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def index():
    return FileResponse("static/index.html")
