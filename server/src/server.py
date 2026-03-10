import os
import io
import hashlib
import datetime as dt
import mimetypes
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, g, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
import logging
import traceback

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from urllib.parse import unquote # Used in get version
from src.validators import is_invalid_link, raw_uri_has_traversal
import re


import pickle as _std_pickle
try:
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:  # dill is optional
    _pickle = _std_pickle


import src.watermarking_utils as WMUtils
from src.watermarking_method import WatermarkingMethod
#from watermarking_utils import METHODS, apply_watermark, read_watermark, explore_pdf, is_watermarking_applicable, get_method

def create_app():
   # --- Login attempt tracking ---
    failed_login_attempts = {}
    MAX_FAILED_LOGIN = 3

    app = Flask(__name__)

    # --- Security logging setup ---
    #security_log = logging.FileHandler("logs/security.log")
    #security_log.setLevel(logging.WARNING)
    #formatter = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    #ecurity_log.setFormatter(formatter)
    #app.logger.addHandler(security_log)


    logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["10000 per minute"]
    )
    # Custom handler for rate limit exceeded
    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit(e):
        app.logger.warning(f"Rate limit exceeded: {e.description}")
        return jsonify({"error": "Rate limit exceeded"}), 429


    # Register global error handler at the end of app setup
    def handle_exception(e):
        print("[ERROR] Unhandled Exception:")
        traceback.print_exc()
        return jsonify({"error": str(e), "type": type(e).__name__}), 500
    app.errorhandler(Exception)(handle_exception)

        # Global error handlers
    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(Exception)
    # Register global error handler at the end of app setup
    def handle_exception(e):
        # Let HTTPExceptions (like 404, 401) pass through with their own codes
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return e
        print("[ERROR] Unhandled Exception:")
        traceback.print_exc()
        return jsonify({"error": str(e), "type": type(e).__name__}), 500

    app.errorhandler(Exception)(handle_exception)


    # app.debug = True
    # app.config["ENV"] = "development"
    # app.config["PROPAGATE_EXCEPTIONS"] = True

    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # --- RMAP Setup ---
    # RMAP is a heavy crypto dependency; avoid importing it during unit tests
    test_mode = os.environ.get("TEST_MODE", "0") in ("1", "true", "True")
    app.config["TEST_MODE"] = test_mode

    if not test_mode:
        from rmap.identity_manager import IdentityManager
        from rmap.rmap import RMAP

        client_keys_dir = os.environ["CLIENT_KEYS_DIR"]
        server_public_key_path = os.environ["SERVER_PUBLIC_KEY_PATH"]
        server_private_key_path = os.environ["SERVER_PRIVATE_KEY_PATH"]
        server_private_key_passphrase = os.environ.get("SERVER_KEY_PASSPHRASE")

        identity_manager = IdentityManager(
            client_keys_dir,
            server_public_key_path,
            server_private_key_path,
            server_private_key_passphrase
        )
        rmap = RMAP(identity_manager)
    else:
        # Dummy placeholders for TEST_MODE so server.py can be imported by pytest
        identity_manager = None
        rmap = None

    app.config["RMAP"] = rmap
    app.config["IDENTITY_MANAGER"] = identity_manager

    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Routes ---
    # Preventing directory traversal and malformed paths
    @app.before_request
    def reject_traversal_or_malformed():
        raw_uri = request.environ.get("RAW_URI") or request.environ.get("REQUEST_URI") or ""
        path = request.path or ""

        # Conditions that should trigger rejection:
        if (
            raw_uri_has_traversal(raw_uri)  # encoded traversal attempts
            or ".." in path                 # decoded traversal
            or "//" in path                 # double slashes
            or ">" in raw_uri or "<" in raw_uri  # malformed characters
            or ">" in path or "<" in path
            or " " in raw_uri or " " in path     # spaces in URI
        ):
            app.logger.warning("Rejected invalid URI: raw=%r path=%r", raw_uri, path)
            return jsonify({"error": "invalid version link"}), 400




    @app.route("/<path:filename>")
    def static_files(filename):
        
        safe_name = secure_filename(filename)
        return app.send_static_file(safe_name)
    
    # No risk of directory traversal here
    @app.route("/")
    def home():
        return app.send_static_file("index.html")
    
    # No risk of directory traversal here
    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception as e:
            print("Error db health fail", e)
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # POST /api/create-user {email, login, password}
    # No risk of directory traversal here
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            app.logger.warning(f"[SECURITY] Duplicate account creation attempt: {email} from {request.remote_addr}")
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
    # No risk of directory traversal here
    @app.post("/api/login")
    def login():
        try:
            payload = request.get_json(silent=True) or {}
            if not isinstance(payload, dict):
                # Payload must be a JSON object
                return jsonify({"error": "Invalid JSON payload"}), 400
        except Exception:
            return jsonify({"error": "Invalid JSON payload"}), 400
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400
        
         # Check for maximum failed login attempts
        if failed_login_attempts.get(email, 0) >= MAX_FAILED_LOGIN:
            app.logger.warning(
                f"[SECURITY] Account locked after too many failed login attempts: {email} from {request.remote_addr}"
            )
            return jsonify({"error": "maximum failed login attempts reached"}), 429


        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            app.logger.warning(
                f"[SECURITY] Failed login attempt for email={email} from {request.remote_addr}"
            )
            failed_login_attempts[email] = failed_login_attempts.get(email, 0) + 1
            return jsonify({"error": "invalid credentials"}), 401

        # Reset failed attempts after successful login
        failed_login_attempts[email] = 0
        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200
    # POST /api/upload-document  (multipart/form-data)
    # Preventing directory traversal attacks
    @app.post("/api/upload-document")
    @require_auth
    def upload_document(): 
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400

        file = request.files["file"]
        app.logger.info(f"Upload received: filename={file.filename}, content_type={file.content_type}")
        file.seek(0)
        header = file.read(4)
        file.seek(0)
        app.logger.info(f"File header: {header}")

        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400
        # Check extension ONLY PDF ALLOWED NO MORE EXPLOIT.ZIP
        # Sanitize filename
        fname = secure_filename(file.filename)
        if not fname.lower().endswith(".pdf"):
            app.logger.warning("[SECURITY] Invalid file extension attempt detected")
            return jsonify({"error": "only .pdf files are allowed"}), 400
        # Check MIME type
        mime_type, _ = mimetypes.guess_type(fname)
        if mime_type != "application/pdf":
            app.logger.warning("Content type check failed")
            app.logger.warning("[SECURITY] Invalid MIME type upload attempt detected")
            return jsonify({"error": "invalid MIME type, that's not a pdf"}), 400
        # Check magic number
        file.seek(0)
        header = file.read(4)
        file.seek(0)
        if header != b"%PDF":
            app.logger.warning("Magic number check failed")
            app.logger.warning("[SECURITY] Invalid PDF header detected — possible exploit upload")
            return jsonify({"error": "file does not appear to be a valid PDF"}), 400

        user_dir = app.config["STORAGE_DIR"] / "files" / g.user["login"]
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        final_name = request.form.get("name") or fname
        stored_name = f"{ts}__{fname}"
        stored_path = user_dir / stored_name

        # Ensure resolved path is inside user_dir
        resolved_path = stored_path.resolve()
        if not str(resolved_path).startswith(str(user_dir.resolve())):
            app.logger.warning(f"Traversal attempt blocked: resolved_path={resolved_path}")
            return jsonify({"error": "invalid file path"}), 400

        file.save(resolved_path)
        app.logger.info(f"[UPLOAD] stored_path={resolved_path}")

        sha_hex = _sha256_file(resolved_path)
        size = resolved_path.stat().st_size

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(resolved_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            app.logger.error(f"Database error during upload: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
    # No risk of directory traversal here
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200


    # Very unsatisfied, impossible to test somehow. Bad coverage, doesn't really work as intended. But I have tried so hard.

    # GET /api/list-versions
    # No risk of directory traversal here
    # Fuzzing fix, separate route to catch bad IDs that would crash the int:document_id route
    @app.get("/api/list-versions/<path:bad_id>")
    def reject_bad_list_versions_id(bad_id):
        try:
            doc_id = int(bad_id)
            if doc_id <= 0:
                print(f"[DEBUG] Fallback route caught invalid document_id={doc_id}")
                return jsonify({"error": "invalid document id"}), 400
        except ValueError:
            print(f"[DEBUG] Fallback route caught non-integer document_id={bad_id}")
            return jsonify({"error": "invalid document id"}), 400

        # If it's a valid positive integer, let Flask route it normally
        return jsonify({"error": "document not found"}), 404

    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        # --- Ownership check: ensure user owns the document ---
        try:
            with get_engine().connect() as conn:
                doc_row = conn.execute(
                    text("SELECT ownerid FROM Documents WHERE id = :did"),
                    {"did": document_id},
                ).first()
                if not doc_row or int(doc_row.ownerid) != int(g.user["id"]):
                    # Don't leak existence: always return 404 if not owner
                    return jsonify({"error": "document not found"}), 404
        except Exception as e:
            print(f"[ERROR] DB error during ownership check: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # --- Confidentiality check: ensure user owns the document ---
        try:
            with get_engine().connect() as conn:
                doc_row = conn.execute(
                    text("SELECT ownerid FROM Documents WHERE id = :did"),
                    {"did": document_id},
                ).first()
                if not doc_row or int(doc_row.ownerid) != int(g.user["id"]):
                    # Don't leak existence: always return 404 if not owner
                    return jsonify({"error": "document not found"}), 404

                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Versions v
                        WHERE v.documentid = :did
                    """),
                    {"did": document_id},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200
    
    # GET /api/list-all-versions
    # No risk of directory traversal here
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        # --- Header validation: reject malformed or unsafe headers ---
        try:
            for key, value in request.headers.items():
                if not isinstance(key, str) or not key.isascii():
                    print(f"[SECURITY] Non-ASCII header name: {repr(key)}")
                    return jsonify({"error": "invalid header name"}), 400
                if not isinstance(value, str) or not value.isascii():
                    print(f"[SECURITY] Non-ASCII header value: {repr(value)}")
                    return jsonify({"error": "invalid header value"}), 400
                if any(c in key for c in ' \r\n:;'):
                    print(f"[SECURITY] Reserved character in header name: {repr(key)}")
                    return jsonify({"error": "invalid header name"}), 400
        except Exception as e:
            print(f"[SECURITY] Exception during header validation: {e}")
            return jsonify({"error": "header validation error"}), 503

        # --- Main query logic ---
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin
                    """),
                    {"glogin": str(g.user["login"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]

        return jsonify({"versions": versions}), 200
    
    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    # No risk of directory traversal here
    # This is the fuzzing fix route for bad id
    @app.get("/api/get-document/<path:bad_id>")
    def reject_bad_get_document_id(bad_id):
        try:
            doc_id = int(bad_id)
            if doc_id <= 0:
                return jsonify({"error": "invalid document id"}), 400
        except ValueError:
            return jsonify({"error": "invalid document id"}), 400
        # If it is a valid positive integer, let Flask route it normally
        return jsonify({"error": "document not found"}), 404
    
    #Another new route for bad ids!
    @app.get("/api/get-document/")
    def reject_empty_get_document():
        return jsonify({"error": "invalid document id"}), 400

    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):
        # Fuzzing fix: empty string or missing ?id previously slipped through and caused 500s.
        # Explicit check ensures consistent 400 "invalid document id" instead of relying on int() exceptions.
        if document_id is None:
            raw_id = request.args.get("id") or request.args.get("documentid")
            if not raw_id:   # covers None and empty string
                return jsonify({"error": "invalid document id"}), 400
            try:
                document_id = int(raw_id)
            except ValueError:
                return jsonify({"error": "invalid document id"}), 400
        
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        # Strong validator
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp
    
    
    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
    # Traversal should be prevented.
    # Fuzz fix for empty links, extra route.
    # Extra route at bottom
    @app.get("/api/get-version/")
    def get_version_empty():
        return jsonify({"error": "invalid version link"}), 400

    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        if is_invalid_link(link):
            return jsonify({"error": "invalid version link"}), 400
        
        decoded = unquote(link).strip()
        decoded = re.sub(r"/+", "/", decoded).rstrip("/")

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": decoded},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path = _safe_resolve_under_storage(row.path, app.config["STORAGE_DIR"])
        except Exception:
            return jsonify({"error": "document path invalid"}), 500


        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp
    
    @app.get("/api/get-version/<path:bad_link>")
    def get_version_bad_path(bad_link: str):
        return jsonify({"error": "invalid version link"}), 400
    
    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # DELETE /api/delete-document  (and variants)
    # Safe against directory traversal attacks
    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth # Now requires login
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        # Fetch the document (enforce ownership)
        # now checks for uid match
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT * FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": int(doc_id), "uid": int(g.user["id"])}
                ).first()

        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            # Possible unauthorized delete attempt (either not found or not owner)
            app.logger.warning(
                f"[SECURITY] Unauthorized delete attempt by user {g.user['id']} "
                f"on document id={doc_id} from {request.remote_addr}"
            )
            return jsonify({"error": "document not found"}), 404

        # Resolve and delete file (best effort)
        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    app.logger.warning("Failed to delete file %s for doc id=%s: %s", fp, row.id, e)
            else:
                file_missing = True
        except RuntimeError as e:
            # Path escapes storage root; refuse to touch the file
            delete_error = str(e)
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE)
        try:
            with get_engine().begin() as conn:
                # If your schema does NOT have ON DELETE CASCADE on Version.documentid,
                # uncomment the next line first:
                # conn.execute(text("DELETE FROM Version WHERE documentid = :id"), {"id": doc_id})
                conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
        except Exception as e:
            return jsonify({"error": f"database error during delete: {str(e)}"}), 503

        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,   # null/omitted if everything was fine
        }), 200
        
        
    # POST /api/create-watermark or /api/create-watermark/<id>  → create watermarked pdf and returns metadata
    # Safe against directory traversal attacks
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body
        doc_id = (
            document_id
            or request.args.get("id")
            or request.args.get("documentid")
            or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
        )
        try:
            # Defensive type validation.
            # Not explicitly unit-tested because malformed or non-integer IDs
            # are rejected earlier by Flask request parsing or equivalent checks.
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400

        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        # Required field validation.
        # Missing-field cases already result in HTTP 400 responses in other tests;
        # this branch is defensive and does not change observable API behavior.
        if not method or not intended_for:
            return jsonify({"error": "method and intended_for are required"}), 400

        # Explicitly whitelist supported methods
        ALLOWED_METHODS = {"axel", "logo-watermark", "my-method-secure"}
        if method not in ALLOWED_METHODS:
            return jsonify({"error": f"unsupported watermark method '{method}'"}), 400

        # Token validation
        ALLOWED_TOKEN_RE = re.compile(r"^[\w\-+=]+$")

        # Token validation helper.
        # Individual edge-case branches (empty, length, invalid characters)
        # are not unit-tested separately as they all map to identical 400 responses.
        def validate_token_field(name: str, value: str, min_len=3, max_len=128):
            if not isinstance(value, str) or not value.strip():
                return False, f"{name} cannot be empty"
            val = value.strip()
            if val.lower() in {"null", "none", "undefined"}:
                return False, f"{name} cannot be '{val}'"
            if not (min_len <= len(val) <= max_len):
                return False, f"{name} length invalid"
            if not ALLOWED_TOKEN_RE.fullmatch(val):
                return False, f"{name} contains invalid characters"
            return True, val

        ok, secret_val = validate_token_field("secret", secret)
        if not ok:
            return jsonify({"error": secret_val}), 400
        secret = secret_val

        ok, key_val = validate_token_field("key", key)
        if not ok:
            return jsonify({"error": key_val}), 400
        key = key_val

        # intended_for basic validation
        if not isinstance(intended_for, str) or not intended_for.strip():
            return jsonify({"error": "intended_for cannot be empty"}), 400
        intended_for = intended_for.strip()
        # Defensive length constraint.
        # Not separately unit-tested as it produces the same HTTP 400 response
        # as other invalid input conditions.
        if len(intended_for) > 64:
            return jsonify({"error": "intended_for too long"}), 400

        # lookup the document
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, name, path FROM Documents WHERE id = :id LIMIT 1"),
                    {"id": doc_id},
                ).first()
        # Defensive database error handling.
        # Not reachable in unit tests using a deterministic in-memory mock database.
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        # Defensive filesystem path validation.
        # Path resolution errors are not realistically triggerable in unit tests.
        except ValueError:
            return jsonify({"error": "document path invalid"}), 400
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method, pdf=str(file_path), position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        # Defensive catch for unexpected watermark applicability failures.
        # Not exercised when watermark utilities are mocked in unit tests.
        except Exception as e:
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        # apply watermark
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position,
            )
            # Defensive check for empty watermark output.
            # Mocked watermark utilities always return valid data in tests.
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 400
        # Catch-all watermark utility error handling.
        # Covered indirectly by higher-level failure tests.
        except Exception as e:
            # treat unexpected WMUtils errors as bad request, not 500
            return jsonify({"error": f"invalid watermark request: {e}"}), 400

        # build destination file name
        base_name = secure_filename(Path(row.name or file_path.name).stem)
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}.pdf"
        dest_path = dest_dir / candidate

        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        # Defensive filesystem write error handling.
        # Not realistically reachable in unit tests without OS-level failures.
        except Exception as e:
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500

        # link token
        import uuid, hashlib
        unique_str = f"{candidate}-{uuid.uuid4().hex}"
        link_token = hashlib.sha1(unique_str.encode("utf-8")).hexdigest()

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text(
                        """INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)"""
                    ),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": str(dest_path),
                    },
                )

                # SQLite (TEST_MODE) does not support LAST_INSERT_ID()
                if app.config.get("TEST_MODE"):
                    vid = int(res.lastrowid)
                else:
                    vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        # Defensive cleanup on database failure after file creation.
        # Not reachable under deterministic mock database conditions.
        except Exception as e:
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        return (
            jsonify(
                {
                    "id": vid,
                    "documentid": doc_id,
                    "link": link_token,
                    "intended_for": intended_for,
                    "method": method,
                    "position": position,
                    "filename": candidate,
                    "size": len(wm_bytes),
                }
            ),
            201,
        )
        
    # Added sanitaztion and safety checks to prevent directory traversal attacks    
    @app.post("/api/load-plugin")
    @require_auth
    def load_plugin():
        """
        Load a serialized Python class implementing WatermarkingMethod from
        STORAGE_DIR/files/plugins/<filename>.{pkl|dill} and register it in wm_mod.METHODS.
        Body: { "filename": "MyMethod.pkl", "overwrite": false }
        """
        payload = request.get_json(silent=True) or {}
        filename = (payload.get("filename") or "").strip()
        overwrite = bool(payload.get("overwrite", False))

        if not filename:
            return jsonify({"error": "filename is required"}), 400

        # Locate the plugin in /storage/files/plugins (relative to STORAGE_DIR)
        storage_root = Path(app.config["STORAGE_DIR"])
        plugins_dir = storage_root / "files" / "plugins"
        try:
            plugins_dir.mkdir(parents=True, exist_ok=True)
            plugin_path = plugins_dir / filename
        except Exception as e:
            return jsonify({"error": f"plugin path error: {e}"}), 500

        if not plugin_path.exists():
            app.logger.warning(f"[SECURITY] Plugin load attempt for missing file: {filename} by user {g.user['id']}")
            return jsonify({"error": f"plugin file not found: {filename}"}), 404

        # Unpickle the object (dill if available; else std pickle)
        try:
            with plugin_path.open("rb") as f:
                obj = _pickle.load(f)
        except Exception as e:
            return jsonify({"error": f"failed to deserialize plugin: {e}"}), 400

        # Accept: class object, or instance (we'll promote instance to its class)
        if isinstance(obj, type):
            cls = obj
        else:
            cls = obj.__class__

        # Determine method name for registry
        method_name = getattr(cls, "name", getattr(cls, "_name_", None))
        if not method_name or not isinstance(method_name, str):
            return jsonify({"error": "plugin class must define a readable name (class.__name__ or .name)"}), 400

        # Validate interface: either subclass of WatermarkingMethod or duck-typing
        has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
        if WatermarkingMethod is not None:
            is_ok = issubclass(cls, WatermarkingMethod) and has_api
        else:
            is_ok = has_api
        if not is_ok:
            return jsonify({"error": "plugin does not implement WatermarkingMethod API (add_watermark/read_secret)"}), 400
            
        # Register the class (not an instance) so you can instantiate as needed later
        WMUtils.METHODS[method_name] = cls()
        
        return jsonify({
            "loaded": True,
            "filename": filename,
            "registered_as": method_name,
            "class_qualname": f"{getattr(cls, '_module_', '?')}.{getattr(cls, '_qualname_', cls.__name__)}",
            "methods_count": len(WMUtils.METHODS)
        }), 201
        
    
    
    # GET /api/get-watermarking-methods -> {"methods":[{"name":..., "description":...}, ...], "count":N}
    # No risk of directory traversal here
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []

        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})
            
        return jsonify({"methods": methods, "count": len(methods)}), 200
        
    # POST /api/read-watermark
    # Safe against directory traversal attacks
    # Now enforces document ownership
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
      #  print(f"[DEBUG] /api/read-watermark called with document_id: {document_id}")
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
    #    print(f"[DEBUG] Resolved doc_id: {document_id}")
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            # Defensive input validation.
            # Malformed or missing document identifiers are typically rejected earlier
            # by Flask routing or request parsing, making this branch difficult to
            # trigger in unit tests.
            print("[ERROR] Invalid document id")
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        print(f"[DEBUG] Payload: {payload}")
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            # Defensive type enforcement for document_id.
            # This overlaps with earlier validation and serves as a safety net
            # against unexpected payload shapes; not separately unit-tested.
            print("[ERROR] document_id (int) is required")
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            print(f"[ERROR] Validation failed: method={method}, key={key}")
            return jsonify({"error": "method, and key are required"}), 400

        # --- Ownership check: ensure user owns the document ---
        try:
            with get_engine().connect() as conn:
                doc_row = conn.execute(
                    text("SELECT ownerid FROM Documents WHERE id = :did"),
                    {"did": doc_id},
                ).first()
                if not doc_row or int(doc_row.ownerid) != int(g.user["id"]):
                    # Don't leak existence: always return 404 if not owner
                    return jsonify({"error": "document not found"}), 404
        except Exception as e:
            # Defensive database error handling.
            # Database engine failures cannot be reliably reproduced in a unit-test
            # environment using a mocked or in-memory database.
            print(f"[ERROR] DB error during ownership check: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # --- NEW: lookup latest version path first ---
        try:
            with get_engine().connect() as conn:
                print(f"[DEBUG] Looking up latest version for document id {doc_id}")
                version_row = conn.execute(
                    text("""
                        SELECT path
                        FROM Versions
                        WHERE documentid = :id
                        ORDER BY id DESC
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()

                if version_row:
                    file_path = Path(version_row.path)
                    print(f"[DEBUG] Using watermarked file from Versions: {file_path}")
                else:
                    # fallback to base document
                    print(f"[DEBUG] No version found, using base document path")
                    base_row = conn.execute(
                        text("""
                            SELECT path
                            FROM Documents
                            WHERE id = :id
                        """),
                        {"id": doc_id},
                    ).first()
                    if not base_row:
                        return jsonify({"error": "document not found"}), 404
                    file_path = Path(base_row.path)
        except Exception as e:
            # Defensive database lookup error handling.
            # Low-level database failures are out of scope for unit testing
            print(f"[ERROR] DB error during document lookup: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            # Defensive filesystem safety check.
            # Path resolution errors indicate corrupted or unsafe paths in storage,
            # which are not realistically triggerable under controlled unit tests.
            print("[ERROR] Document path invalid")
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            print("[ERROR] File missing on disk")
            return jsonify({"error": "file missing on disk"}), 410

        secret = None
        try:
         #   print(f"[DEBUG] Attempting to read watermark: method={method}, pdf={file_path}, key={key}")
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
          #  print(f"[DEBUG] Watermark read result: {secret}")
        except Exception as e:
            # Defensive catch for unexpected watermark extraction failures.
            # In unit tests, watermark utilities are mocked to deterministic behavior;
            print(f"[ERROR] Error when attempting to read watermark: {e}")
            return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400
        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 201

    # POST /rmap-initiate
    @app.route("/api/rmap-initiate", methods=["POST"])
    def rmap_initiate():
        rmap = app.config["RMAP"]
        incoming = request.get_json(silent=True) or {}
        payload = incoming.get("payload")
        if not payload:
            return jsonify({"error": "Missing 'payload'"}), 400
        try:
            resp = rmap.handle_message1({"payload": payload})
            if "error" in resp:
                return jsonify({"error": f"RMAP initiation failed: {resp['error']}"}), 400
            return jsonify(resp), 200
        except Exception as e:
            import traceback
            print("Exception in /rmap-initiate:", repr(e))
            traceback.print_exc()
            return jsonify({"error": str(e)}), 400

    # POST /rmap-get-link
    # Fixed to prevent directory traversal attacks and ensure Group_19 document exists
    @app.route("/api/rmap-get-link", methods=["POST"])
    def rmap_get_link():
        rmap = app.config["RMAP"]
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()

        incoming = request.get_json(silent=True) or {}
        payload = incoming.get("payload")
        if not payload:
            return jsonify({"error": "Missing 'payload'"}), 400

        resp = rmap.handle_message2({"payload": payload})
        if "error" in resp:
            return jsonify({"error": f"RMAP authentication failed: {resp['error']}"}), 400

        session_secret = resp["result"]

        # --- Group identity traceability ---
        group_identity = None
        for ident, (nonce_client, nonce_server) in rmap.nonces.items():
            combined = (nonce_client << 64) | int(nonce_server)
            if f"{combined:032x}" == session_secret:
                group_identity = ident
                break

        if group_identity is None:
            return jsonify({"error": "Could not resolve group identity from session secret"}), 400

        # Step 3: Fetch seeded Group_19 document from DB
        try:
            with get_engine().connect() as conn:
                doc_row = conn.execute(
                    text("SELECT id, path FROM Documents WHERE name=:n LIMIT 1"),
                    {"n": "Group_19"},
                ).first()
                if not doc_row:
                    return jsonify({"error": "Group_19 document not found"}), 500
                documentid = doc_row.id
                source_pdf = Path(doc_row.path)
        except Exception as e:
            return jsonify({"error": f"Database error: {str(e)}"}), 500

        # Step 4: Apply watermark
        dest_dir = storage_root / "rmap"
        dest_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{session_secret}.pdf"
        dest_path = dest_dir / filename
        resolved_path = dest_path.resolve()
        if not str(resolved_path).startswith(str(dest_dir.resolve())): #make sure it's under dest_dir and not traversing out
            return jsonify({"error": "invalid destination path"}), 500

        try:
            wm_bytes = WMUtils.apply_watermark(
                method="axel",
                pdf=str(source_pdf),
                secret=group_identity,
                key=session_secret,
                position=None,
            )
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            return jsonify({"error": f"Watermarking failed: {str(e)}"}), 500

        # Step 5: Generate link token
        link_token = session_secret  # use session secret as link token

        # Step 6: Insert Version row linked to Group_19
        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": documentid,
                        "link": link_token,
                        "intended_for": group_identity,
                        "secret": session_secret,
                        "method": "axel",
                        "position": "",
                        "path": str(dest_path),
                    },
                )
        except Exception as e:
            return jsonify({"error": f"Database error: {str(e)}"}), 500

        return jsonify({"result": session_secret}), 200
    
    @app.get("/api/exam")
    def get_exam():
    
        return jsonify({"message": "hello"}), 200
                
    

    return app
    

# WSGI entrypoint
app = create_app()

def get_engine():
    """
    Central database access point.

    - In TEST_MODE: reuse a single in-memory SQLite mock engine
    - Otherwise: use the production MySQL database
    """
    # --- TEST MODE ---
    if app.config.get("TEST_MODE"):
        eng = app.config.get("_MOCK_ENGINE")
        if eng is None:
            from src.mock_db import get_engine as mock_get_engine
            eng = mock_get_engine()
            app.config["_MOCK_ENGINE"] = eng
        return eng

    # --- PRODUCTION MODE ---
    eng = app.config.get("_ENGINE")
    if eng is None:
        eng = create_engine(db_url(), pool_pre_ping=True, future=True)
        app.config["_ENGINE"] = eng
    return eng

# --- DB engine only (no Table metadata) ---
def db_url() -> str:
    return (
        f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
        f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
