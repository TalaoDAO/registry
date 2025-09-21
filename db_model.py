from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone
from jwcrypto import jwk 
import json
from utils.kms import encrypt_json
from utils import oidc4vc
from sqlalchemy import CheckConstraint, Enum, UniqueConstraint, Index

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150))
    registration = db.Column(db.String(256)) # wallet/google/...
    given_name = db.Column(db.String(256))
    family_name = db.Column(db.String(256))
    login = db.Column(db.String(256),  unique=True)
    name = db.Column(db.String(256),  unique=True)
    sub = db.Column(db.String(256),  unique=True)
    subscription = db.Column(db.String(256)) # free/....
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    usage_quota = db.Column(db.Integer, default=1000)
    organization = db.Column(db.String(256))
    billing_id = db.Column(db.String(128))
    country = db.Column(db.String(64))
    signins = db.relationship("Signin", backref="user", lazy=True)
    role = db.Column(db.String(64), default="user")
    profile_picture = db.Column(db.String(256), default ="default_picture.jpeg")  
    deleted_at = db.Column(db.DateTime(timezone=True))# stores filename or URL


# Flask-Login user loader
def load_user(user_id):
    return User.query.get(int(user_id))


def default_verifier_encryption_key():
    key = jwk.JWK.generate(kty='EC', crv='P-256', alg='ES256')
    # Set additional parameters manually
    key_dict = json.loads(key.export(private_key=True))
    key_dict["alg"] = "ECDH-ES"
    key_dict["use"] = "enc"
    #key_dict["kid"] = "ac"
    return key_dict


def default_verifier_request_key():
    key = jwk.JWK.generate(kty="EC", crv="P-256", alg="ES256")
    return json.loads(key.export(private_key=True))


class VCTRegistry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    # identifiers
    vct = db.Column(db.Text)                          # public URL (resolver)
    vct_urn = db.Column(db.Text)                      # original VCT identifier as an urn.
    integrity = db.Column(db.String(128), nullable=False, unique=True)
    integrity_v2 = db.Column(db.String(256), index=True)
    # presentation
    name = db.Column(db.String(128))
    description = db.Column(db.Text)
    languages_supported = db.Column(db.Text, default="[]") # an array of all languages supported
    vct_data = db.Column(db.Text)
    schema_hash = db.Column(db.String(64), index=True, nullable=True)
    # visibility + search
    is_public = db.Column(db.Boolean, default=False, nullable=False, index=True)
    keywords = db.Column(db.Text)                     # comma-separated lowercase tokens
    search_text = db.Column(db.Text)                  # aggregated searchable text
    # popularity
    calls_count = db.Column(db.Integer, default=0, nullable=False, index=True)
    ratings_count = db.Column(db.Integer, default=0, nullable=False)
    ratings_sum = db.Column(db.Integer, default=0, nullable=False)
    avg_rating = db.Column(db.Float, default=0.0, nullable=False)
    # timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = db.Column(db.DateTime(timezone=True))
    extra = db.Column(db.Text)
    __table_args__ = (
        Index('ix_vctregistry_owner_created', 'user_id', 'created_at'),
        Index('ix_vctregistry_integrity_v2', 'integrity_v2'),
        Index('ix_vctregistry_name', 'name'),
        Index('ix_vctregistry_public_created', 'is_public', 'created_at'),
        Index('ix_vctregistry_search_text', 'search_text'),
        Index('ix_vctregistry_calls', 'calls_count'),
    )


class VCTRating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vct_id = db.Column(db.Integer, db.ForeignKey("vct_registry.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    stars = db.Column(db.Integer, nullable=False)  # 1..5
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    __table_args__ = (
        UniqueConstraint('vct_id', 'user_id', name='uq_vct_rating_per_user'),
        CheckConstraint('stars BETWEEN 1 AND 5', name='ck_stars_range'),
    )

class Signin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(128), nullable=False, unique=True)
    description = db.Column(db.Text)
    signin_type = db.Column(Enum("sandbox", "qualified", name="signin_type"))
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now, nullable=False)
    client_id_scheme = db.Column(db.String(64), default="redirect_uri", nullable=False)
    client_id = db.Column(db.String(256))
    presentation_format = db.Column(Enum("presentation_exchange", "dcql_query", name="presentation_format"), default="presentation_exchange")
    landing_page = db.Column(db.String(256), default="google_style", nullable=False)
    response_mode = db.Column(Enum("direct_post", "direct_post.jwt", name="response_mode", default="direct_post"))
    credential_id = db.Column(db.String(256))
    credential_id_for_encryption = db.Column(db.String(256))
    signin_info = db.Column(db.Text, default="{}")
    signin_metadata = db.Column(db.Text, default="{}")
    application_api = db.Column(db.Text, nullable=False)
    application_api_client_id = db.Column(db.String(64), nullable=False, index=True)
    response_encryption = db.Column(db.Boolean, default=False, nullable=False)
    draft = db.Column(db.String(64), default="20", nullable=False)
    prefix = db.Column(db.String(64), default="openid4vp://", nullable=False)
    log = db.Column(db.Boolean, default=False, nullable=False)
    test = db.Column(db.String(256), default="")
    dc_api = db.Column(db.Boolean, default=False, nullable=False)


class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)   # internal identifier
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    credential_id = db.Column(db.Text, unique=True)
    credential_type = db.Column(Enum("sandbox", "qualified", name="credential_type"), default="sandbox")
    use = db.Column(Enum("enc", "sign", name="use"), default="sign")
    description = db.Column(db.Text)
    key = db.Column(db.Text)  
    public_key = db.Column(db.Text, nullable=False)
    certificate = db.Column(db.Text)
    x5c = db.Column(db.Text) # trust chain
    did = db.Column(db.Text)
    verification_method = db.Column(db.Text)
    #verifier_attestation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    provider = db.Column(db.String(64))
    san_dns = db.Column(db.String(64))
    san_uri = db.Column(db.String(256))
    exp = db.Column(db.DateTime)

class VCTImportLog(db.Model):
    """
    Audit + idempotency for issuer imports.
    We keep a content hash of the issuer SD-JWT configuration so re-running
    on the same metadata state doesn't create duplicates, while changes
    at the issuer are imported again (new hash).
    """
    id = db.Column(db.Integer, primary_key=True)

    issuer_url = db.Column(db.String(512), index=True, nullable=False)
    config_id = db.Column(db.String(256), index=True, nullable=False)
    config_vct = db.Column(db.String(512))   # issuer-advertised vct (if any)
    config_hash = db.Column(db.String(64), index=True, nullable=False)  # base64url sha256 of cfg JSON

    imported_vct_urn = db.Column(db.String(128), index=True)
    imported_integrity = db.Column(db.String(128))
    imported_row_id = db.Column(db.Integer, index=True)

    status = db.Column(db.String(16), index=True, nullable=False, default="pending")  # pending|success|skipped|error
    error_message = db.Column(db.Text)

    raw_snapshot = db.Column(db.Text)  # full JSON of the config at the time of import
    http_status = db.Column(db.String(16))
    duration_ms = db.Column(db.Integer)
    attempts = db.Column(db.Integer, default=0)
    worker = db.Column(db.String(128))

    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        # Fast lookups and uniqueness guard:
        # same issuer + same config_id + same content_hash → already imported
        # (we don't make it STRICT unique to allow manual repairs, but we index it
        db.Index('ix_vctimport_status_created', 'status', 'created_at'),
        db.Index("ix_vctimport_unique", "issuer_url", "config_id", "config_hash"),
    )


def seed_credential():
    if not Credential.query.first():
        try:
            with open('keys.json') as f:
                keys = json.load(f)
            credentials = keys.get("credentials")
        except Exception:
            return
        for credential in credentials:
            default_key = Credential(
                user_id=1,
                credential_id=credential["credential_id"],
                credential_type=credential["credential_type"],
                use=credential["use"],
                description=credential["description"],
                provider=credential["provider"],
                key=encrypt_json(credential.get("key", {})),
                public_key=json.dumps(credential.get("public_key", {})),
                certificate=credential.get("certificate"),
                x5c=json.dumps(credential.get("x5c", [])),
                did=credential.get("did"),
                verification_method=credential.get("verification_method"),
                #verifier_attestation=credential.get("verifier_attestation"),
                san_dns=oidc4vc.extract_first_san_dns_from_der_b64(credential.get("certificate")),
                san_uri=oidc4vc.extract_first_san_uri_from_der_b64(credential.get("certificate")),
                exp=oidc4vc.extract_expiration(credential.get("certificate"))
            )
            db.session.add(default_key)
        db.session.commit()


def seed_signin_for_wallet_registration(mode):
    if not Signin.query.first():
        application_api = {
            "url": mode.server + "signin/app",
            "client_id": "0000",
            "client_secret": "0000"
        }
        default_signin = Signin(
            user_id=1,
            name="Wallet_onboarding",
            signin_type="sandbox",
            description="This is a signin for wallet onboarding",
            client_id_scheme="redirect_uri",
            client_id=mode.server + "signin/wallet/callback",
            landing_page="google_style",
            response_mode="direct_post",
            credential_id="signature_key_1",
            application_api=encrypt_json(application_api),
            application_api_client_id="0000",
            response_encryption=False,
            prefix="openid-vc://"
        )
        db.session.add(default_signin)
        db.session.commit()


def seed_user():
    if not User.query.first():
        
        default_user = User(
            email="contact@talao.io",
            created_at=datetime.now(timezone.utc),
            registration="seed",
            name="admin",
            role="admin",
            organization="Web3 Digital Wallet",
            country="FR",
            subscription="paid",
            profile_picture="default_picture.jpeg",
        )
        db.session.add(default_user)
        
        default_user = User(
            email="contact@talao.io",
            created_at=datetime.now(timezone.utc),
            registration="seed",
            name="test",
            organization="Web3 Digital Wallet",
            country="FR",
            subscription="free",
            role="user",
            profile_picture="default_picture.jpeg",
        )
        db.session.add(default_user)
        
        default_user = User(
            email="contact@talao.io",
            created_at=datetime.now(timezone.utc),
            registration="seed",
            name="test_paid",
            role="user",
            organization="Web3 Digital Wallet",
            country="FR",
            subscription="paid",
            profile_picture="default_picture.jpeg",
        )
        db.session.add(default_user)
        
        robot_email = "thierry.thevenet@talao.io"
        if not User.query.filter_by(email=robot_email).first():
            robot = User(
                email=robot_email,
                name="robot",               # as requested
                role="user",
                registration="seed",
                created_at=datetime.now(timezone.utc),
            )
            db.session.add(robot)
        
        db.session.commit()


class VCTRegistryLanguage(db.Model):
    __tablename__ = "vct_registry_languages"
    vct_id = db.Column(db.Integer, db.ForeignKey("vct_registry.id", ondelete="CASCADE"), primary_key=True)
    lang_code = db.Column(db.String(16), primary_key=True)
    __table_args__ = (
        db.Index("ix_vct_registry_lang_code", "lang_code"),
    )

class VCTRegistryMeta(db.Model):
    __tablename__ = "vct_registry_meta"
    vct_id = db.Column(db.Integer, db.ForeignKey("vct_registry.id", ondelete="CASCADE"), primary_key=True)
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text)
    __table_args__ = (
        db.Index("ix_vct_registry_meta_key", "key"),
    )
