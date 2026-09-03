from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..security import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _slugify(name: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")
    return slug or "org"


@router.post("/register", response_model=schemas.TokenResponse)
def register(body: schemas.RegisterRequest, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.email == body.email.lower()).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    slug = _slugify(body.organization_name)
    base = slug
    n = 1
    while db.query(models.Organization).filter(models.Organization.slug == slug).first():
        n += 1
        slug = f"{base}-{n}"
    org = models.Organization(name=body.organization_name, slug=slug)
    db.add(org)
    db.flush()
    user = models.User(
        organization_id=org.id,
        email=body.email.lower(),
        password_hash=hash_password(body.password),
        full_name=body.full_name,
        role="admin",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(user.id, org.id)
    return schemas.TokenResponse(access_token=token)


@router.post("/login", response_model=schemas.TokenResponse)
def login(body: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == body.email.lower()).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(user.id, user.organization_id)
    return schemas.TokenResponse(access_token=token)


@router.get("/me", response_model=schemas.MeResponse)
def me(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    org = (
        db.query(models.Organization)
        .filter(models.Organization.id == user.organization_id)
        .first()
    )
    return schemas.MeResponse(user=user, organization=org)
