# apis/signin_api.py
from flask import Blueprint
from flask_restx import Api, Namespace, Resource, fields
from werkzeug.exceptions import BadRequest

from routes.signin.bridge import (
    oidc_authorize, oidc_token, oidc_logout, oidc_userinfo,
    oidc_openid_configuration, oidc_jwks,
)

# Mount all verifier "app" endpoints under /signin
bp = Blueprint("signin_app", __name__, url_prefix="/signin")

# Bind RESTX to the blueprint; Swagger UI at /signin/swagger
api_signin = Api(
    bp,
    version="1.0",
    title="CONNECTORS Verifier API",
    description="OpenID endpoints for applications to bridge with the OIDC4VP Verifier.",
    doc="/swagger",
)

# Namespace => routes will be /signin/app/<endpoint>
ns = Namespace("app", description="OpenID endpoints for customer application")
api_signin.add_namespace(ns, path="")

# ------------------------------------------------------------
# Models
# ------------------------------------------------------------
error_model = ns.model("Error", {
    "error": fields.String(example="invalid_request"),
    "error_description": fields.String(example="missing redirect_uri"),
})

authorize_success = ns.model("AuthorizeRedirect", {
    "location": fields.String(example="https://client.example.com/cb?code=abc123&state=xyz"),
})

token_response = ns.model("TokenResponse", {
    "id_token": fields.String,
    "access_token": fields.String,
    "token_type": fields.String(example="Bearer"),
    "expires_in": fields.Integer(example=2000),
})

userinfo_response = ns.model("UserInfoResponse", {
    "sub": fields.String,
    "vp_token": fields.Raw,
})

openid_config = ns.model("OpenIdConfiguration", {
    "issuer": fields.String,
    "authorization_endpoint": fields.String,
    "token_endpoint": fields.String,
    "userinfo_endpoint": fields.String,
    # Support either name depending on your implementation:
    "logout_endpoint": fields.String,
    "end_session_endpoint": fields.String,
    "jwks_uri": fields.String,
    "scopes_supported": fields.List(fields.String),
    "response_types_supported": fields.List(fields.String),
    "token_endpoint_auth_methods_supported": fields.List(fields.String),
    "id_token_signing_alg_values_supported": fields.List(fields.String),
})

jwks_model = ns.model("JWKS", {
    "keys": fields.List(fields.Raw)
})

# ------------------------------------------------------------
# Parsers (standard OIDC inputs)
# ------------------------------------------------------------
authorize_parser = ns.parser()
authorize_parser.add_argument("response_type", required=True, choices=("code", "id_token"),
                            location="args", help="OIDC response type.")
authorize_parser.add_argument("client_id", required=True, location="args",
                            help="RP client identifier.")
authorize_parser.add_argument("redirect_uri", required=True, location="args",
                            help="RP redirect URI.")
authorize_parser.add_argument("scope", required=True, location="args",
                            help='Space-delimited scopes, used to provide the VC type requested to the wallet. Example "PID" ')
authorize_parser.add_argument("state", location="args",
                            help="Opaque value returned unmodified.")
authorize_parser.add_argument("nonce", location="args",
                            help="Replay protection for ID Token.")
authorize_parser.add_argument("code_challenge", location="args",
                            help="PKCE challenge (S256/plain).")
authorize_parser.add_argument("code_challenge_method", location="args", choices=("S256", "plain"),
                            help="PKCE method.")
authorize_parser.add_argument("response_mode", location="args", choices=("query", "fragment"),
                            help="How parameters are returned to the redirect_uri.")
authorize_parser.add_argument("authorization_details", location="args",
                            help="URL encoded JSON string describing the transaction_data of OIDC4VP .")

token_parser = ns.parser()
token_parser.add_argument("Authorization", location="headers",
                        help='HTTP Basic auth: Basic base64(client_id:client_secret).')
token_parser.add_argument("grant_type", required=True, location="form",
                        choices=("authorization_code",),
                        help="OAuth2 grant type.")
token_parser.add_argument("code", required=True, location="form",
                        help="Authorization code from /authorize.")
token_parser.add_argument("redirect_uri", required=True, location="form",
                        help="Same redirect_uri as sent to /authorize.")
token_parser.add_argument("code_signin", location="form",
                        help="PKCE code_signin matching code_challenge.")
# Alternative client auth (client_secret_post):
token_parser.add_argument("client_id", location="form",
                        help="Client ID if using client_secret_post.")
token_parser.add_argument("client_secret", location="form",
                        help="Client secret if using client_secret_post.")

userinfo_parser = ns.parser()
userinfo_parser.add_argument("Authorization", required=True, location="headers",
                            help="Bearer access_token issued by /token. Example: Bearer eyJ...")

logout_parser = ns.parser()
logout_parser.add_argument("post_logout_redirect_uri", location="args",
                        help="Where to send the user after logout (relative/same-origin recommended).")
logout_parser.add_argument("state", location="args",
                        help="Opaque value to be echoed back.")
logout_parser.add_argument("id_token_hint", location="args",
                        help="(Optional) ID Token to help identify the session.")

# ------------------------------------------------------------
# Resources
# ------------------------------------------------------------
@ns.route("/authorize")
class Authorize(Resource):
    @ns.expect(authorize_parser, validate=True)
    @ns.response(302, "Redirect on success", model=authorize_success)
    @ns.response(400, "Bad request", model=error_model)
    @ns.response(401, "Unauthorized", model=error_model)
    def get(self):
        return oidc_authorize()

   

@ns.route("/token")
class Token(Resource):
    @ns.doc(consumes=["application/x-www-form-urlencoded"])
    @ns.expect(token_parser, validate=True)
    @ns.marshal_with(token_response, code=200)
    @ns.response(400, "Bad request", model=error_model)
    @ns.response(401, "Unauthorized", model=error_model)
    def post(self):
        return oidc_token()


@ns.route("/userinfo")
class UserInfo(Resource):
    @ns.expect(userinfo_parser, validate=True)
    @ns.marshal_with(userinfo_response, code=200)
    @ns.response(401, "Invalid or expired token", model=error_model)
    def get(self):
        return oidc_userinfo()

    # If you want to accept POST with bearer in header as well:
    @ns.expect(userinfo_parser, validate=True)
    def post(self):
        return oidc_userinfo()

@ns.route("/logout")
class Logout(Resource):
    @ns.expect(logout_parser)
    @ns.response(302, "Redirect back to application")
    def get(self):
        return oidc_logout()

    @ns.expect(logout_parser)
    def post(self):
        return oidc_logout()

@ns.route("/.well-known/openid-configuration")
class OpenIdConfig(Resource):
    @ns.marshal_with(openid_config, code=200)
    def get(self):
        return oidc_openid_configuration()

@ns.route("/jwks.json")
class JWKS(Resource):
    @ns.marshal_with(jwks_model, code=200)
    def get(self):
        return oidc_jwks()

def init_app(app):
    app.register_blueprint(bp)
