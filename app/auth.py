# app/auth.py
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from .models import User, db
import logging
import os
from dotenv import load_dotenv
from datetime import datetime
import json
from typing import Optional, List, Dict, Tuple
from sqlalchemy import or_

from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE, BASE

load_dotenv()
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, log_level, logging.INFO))
logger = logging.getLogger("app.auth")

auth_bp = Blueprint("auth", __name__)

LDAP_URL = os.getenv("LDAP_URL")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN")

# Admin local via .env (opcional)
LOCAL_ADMIN_EMAIL = os.getenv("LOCAL_ADMIN_EMAIL")
LOCAL_ADMIN_USERNAME = os.getenv("LOCAL_ADMIN_USERNAME", "admin")
LOCAL_ADMIN_PASSWORD = os.getenv("LOCAL_ADMIN_PASSWORD")

# Mapeamento de cargo/grupo -> role (opcional, via .env)
# Ex.: "DIRETOR:diretor;GERENTE SENIOR:gerente senior;GERENTE:gerente;COORDENADOR:gerente;GESTOR:gestor"
ROLE_MAP = os.getenv("ROLE_MAP", "")
# Força o AD a sobrescrever mesmo se role_source == 'ADMIN'
ROLE_MAP_FORCE = os.getenv("ROLE_MAP_FORCE", "false").lower() in ("1", "true", "yes")

# Fallback do Excel habilitado?
USE_EXCEL_FALLBACK = os.getenv("USE_EXCEL_FALLBACK", "true").lower() in ("1", "true", "yes")

# Lista de títulos permitidos no PRIMEIRO LOGIN (comparação EXATA, em uppercase)
FIRST_LOGIN_ALLOWED_TITLES = os.getenv(
    "FIRST_LOGIN_ALLOWED_TITLES",
    "VP ENGENHARIA E SERVICOS AO CLIENTE;DIR SERV AO CLIENTE CENTRALIZADO;DIR SERVICOS AO CLIENTE CW;GER SR SERVICO AO CLIENTE;GERENTE SERVICO AO CLIENTE;COORDENADOR SERVICO AO CLIENTE;SUPERVISOR SERVICOS AO CLIENTE"
)
FIRST_LOGIN_ALLOWED_TITLES = [t.strip().upper() for t in FIRST_LOGIN_ALLOWED_TITLES.split(";") if t.strip()]


def _parse_ldap_url(raw: str):
    if not raw or not raw.strip():
        raise ValueError("LDAP_URL vazio ou ausente")
    value = raw.strip()
    use_ssl = False
    port = None
    host = value

    if host.lower().startswith("ldaps://"):
        host = host[8:]
        use_ssl = True
        port = 636
    elif host.lower().startswith("ldap://"):
        host = host[7:]
        use_ssl = False
        port = 389

    if ":" in host:
        h, p = host.rsplit(":", 1)
        if p.isdigit():
            host = h
            port = int(p)

    if port is None:
        port = 636 if use_ssl else 389

    host = host.strip()
    if not host:
        raise ValueError("Host LDAP inválido após parsing")

    return host, port, use_ssl


def _guess_upn(identifier: str, ldap_host: str) -> str:
    """
    Se o usuário digitou apenas sAMAccountName (sem '@' e sem '\\'),
    montamos UPN automaticamente: usuario@<dominio_do_ldap>
    """
    if not identifier or "@" in identifier or "\\" in identifier:
        return identifier
    dominio = ldap_host
    if ":" in dominio:
        dominio = dominio.split(":", 1)[0]
    return f"{identifier}@{dominio}"


def authenticate_ad(identifier: str, password: str):
    """
    Autentica no AD via UPN/sAMAccountName e retorna dados do usuário,
    incluindo (se disponível) o DN, 'title' (cargo), 'memberOf' (grupos) e atributos do 'manager'.
    """
    if not LDAP_URL or not LDAP_BASE_DN:
        logger.error("Configuração LDAP ausente. Verifique LDAP_URL e LDAP_BASE_DN no .env.")
        return None

    try:
        host, port, use_ssl = _parse_ldap_url(LDAP_URL)
        logger.info(f"LDAP server configurado: host={host}, port={port}, ssl={use_ssl}")
    except Exception as e:
        logger.error(f"Config LDAP inválida: {e}")
        return None

    server = Server(host=host, port=port, get_info=ALL, use_ssl=use_ssl)

    candidates = [identifier]
    upn_guess = _guess_upn(identifier, host)
    if upn_guess != identifier:
        candidates.append(upn_guess)

    last_error = None
    for candidate in candidates:
        try:
            conn = Connection(
                server,
                user=candidate,
                password=password,
                authentication=SIMPLE,
                auto_bind=True
            )
            # Busca por UPN e SAM do candidate e também do identifier original
            search_filter = (
                f"(|(userPrincipalName={candidate})(sAMAccountName={candidate})"
                f"(userPrincipalName={identifier})(sAMAccountName={identifier}))"
            )
            conn.search(
                search_base=LDAP_BASE_DN,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[
                    "mail", "sAMAccountName", "displayName", "distinguishedName",
                    "manager", "title", "department", "memberOf"
                ]
            )
            if not conn.entries:
                logger.warning(f"Nenhuma entrada encontrada para {identifier} (candidate={candidate}).")
                conn.unbind()
                continue

            entry = conn.entries[0]
            mail = str(entry.mail.value) if entry.mail else None
            username = str(entry.sAMAccountName.value) if entry.sAMAccountName else None
            display_name = str(entry.displayName.value) if entry.displayName else (username or identifier)
            dn = str(entry.entry_dn)
            title = str(entry.title.value) if hasattr(entry, "title") and entry.title else None
            department = str(entry.department.value) if hasattr(entry, "department") and entry.department else None

            # memberOf pode ser multi-valor (grupos)
            groups = []
            try:
                if hasattr(entry, "memberOf") and entry.memberOf:
                    groups = [str(g) for g in entry.memberOf.values]
            except Exception:
                groups = []

            # Buscar dados do gestor
            manager_info = None
            manager_dn = str(entry.manager.value) if hasattr(entry, "manager") and entry.manager else None
            if manager_dn:
                try:
                    conn.search(
                        search_base=manager_dn,
                        search_filter="(objectClass=person)",
                        search_scope=BASE,
                        attributes=["mail", "displayName", "sAMAccountName", "userPrincipalName"]
                    )
                    if conn.entries:
                        m = conn.entries[0]
                        m_mail = str(m.mail.value) if m.mail else None
                        m_upn = str(m.userPrincipalName.value) if hasattr(m, "userPrincipalName") and m.userPrincipalName else None
                        m_sam = str(m.sAMAccountName.value) if m.sAMAccountName else None
                        m_display = str(m.displayName.value) if m.displayName else (m_sam or m_upn or "GESTOR")
                        manager_info = {
                            "dn": manager_dn,
                            "email": m_mail or m_upn,
                            "username": m_sam or (m_upn.split("@")[0] if m_upn else None),
                            "display_name": m_display
                        }
                except Exception as e:
                    logger.warning(f"Não foi possível buscar o gestor ({manager_dn}): {e}")

            conn.unbind()
            return {
                "email": mail or identifier,
                "username": username or identifier,
                "display_name": display_name,
                "dn": dn,
                "manager": manager_info,
                "title": title,
                "department": department,
                "groups": groups,
            }
        except Exception as e:
            last_error = e
            logger.warning(f"Falha no bind AD com '{candidate}': {e}")

    if last_error:
        logger.error(f"Erro na autenticação AD (todas as tentativas falharam): {last_error}")
    return None


def _parse_role_map(env_value: str) -> Dict[str, str]:
    """
    Converte "CHAVE:valor;CHAVE2:valor2" em dict {"CHAVE": "valor", ...}
    As CHAVES são comparadas por substring no TITLE/GRUPOS (upper).
    """
    mapping = {}
    for pair in (env_value or "").split(";"):
        if ":" in pair:
            k, v = pair.split(":", 1)
            k = k.strip().upper()
            v = v.strip()
            if k and v:
                mapping[k] = v
    return mapping


def map_role_from_ad(title: Optional[str], groups: Optional[List[str]]) -> Optional[str]:
    """
    Define o role a partir de title/groups do AD usando ROLE_MAP; fallback por heurística.
    """
    title_up = (title or "").upper()
    groups_up = [g.upper() for g in (groups or [])]
    mapping = _parse_role_map(ROLE_MAP)

    # 1) Procura por chaves do mapping no title
    for key, val in mapping.items():
        if key and key in title_up:
            return val

    # 2) Procura por chaves do mapping nos nomes DN de grupos
    for key, val in mapping.items():
        if any(key in g for g in groups_up):
            return val

    # 3) Heurísticas padrão (caso não tenha ROLE_MAP)
    if "DIRETOR" in title_up:
        return "diretor"
    if "GERENTE" in title_up and ("SENIOR" in title_up or "SR" in title_up):
        return "gerente senior"
    if "GERENTE" in title_up or "COORDENADOR" in title_up or "COORD." in title_up:
        return "gerente"
    if "GESTOR" in title_up or "SUPERVISOR" in title_up:
        return "gestor"

    return None


def _get_or_create_user(email: str, nome: str) -> Tuple[Optional[User], bool]:
    """
    Retorna (user, created_now).
    Se usuário estiver inativo, retorna ("INATIVO", False).
    """
    if not email:
        logger.error("Tentativa de criar/obter usuário sem email.")
        return None, False

    user = User.query.filter_by(email=email).first()
    if not user:
        # Garante username único com base no nome ou prefixo do email
        base_username = (nome or email.split("@")[0]).strip() or email.split("@")[0]
        candidate = base_username
        suffix = 2

        while User.query.filter_by(username=candidate).first():
            candidate = f"{base_username}{suffix}"
            suffix += 1

        user = User(
            email=email,
            username=candidate,
            password="ad_auth_placeholder",
            auth_type="ad"  # Indicar que é um usuário do AD
        )
        if hasattr(user, "status"):
            user.status = "ATIVO"
        if hasattr(user, "ultimo_login"):
            user.ultimo_login = datetime.utcnow()

        db.session.add(user)
        db.session.commit()
        logger.info(f"Novo usuário criado: {email}")
        return user, True
    else:
        if hasattr(user, "ultimo_login"):
            user.ultimo_login = datetime.utcnow()
        db.session.commit()

        if hasattr(user, "status") and user.status != "ATIVO":
            logger.info(f"Usuário {email} está inativo.")
            return "INATIVO", False

    return user, False


def _build_session(user):
    session["usuario"] = {
        "id": getattr(user, "id", None),
        "nome": getattr(user, "username", "USUARIO"),
        "email": getattr(user, "email", None),
        "gestor_id": getattr(user, "gestor_id", None),
        "gestor_nome": getattr(getattr(user, "gestor", None), "username", None),
        "gestor_email": getattr(getattr(user, "gestor", None), "email", None),
        "role": getattr(user, "role", "user"),
    }


# --- Fallback: autenticação local (apenas admin ou usuários locais criados) ---

def _authenticate_local_admin(identifier: str, password: str):
    """
    Tenta autenticar um admin local por email OU username.
    Retorna o User se ok; senão, None.
    """
    if not identifier or not password:
        return None

    q = User.query.filter(
        or_(User.email == identifier, User.username == identifier)
    ).first()
    if not q:
        return None

    if q.role != "admin":
        logger.warning("Tentativa de login local com usuário não-admin bloqueada.")
        return None

    if q.check_password(password):
        # Garantir que o tipo de autenticação está correto
        if q.auth_type != "local":
            q.auth_type = "local"
            db.session.commit()
        return q
    return None


def _authenticate_local_user(identifier: str, password: str):
    """
    Tenta autenticar qualquer usuário local por email OU username.
    Retorna o User se ok; senão, None.
    """
    if not identifier or not password:
        return None

    q = User.query.filter(
        or_(User.email == identifier, User.username == identifier)
    ).first()
    if not q:
        return None

    # Somente usuários com auth_type 'local' podem fazer login local
    if q.auth_type != "local":
        return None

    if q.check_password(password):
        return q
    return None


# --- Seed automático do admin local via .env (se configurado) ---
def _ensure_local_admin_seed():
    if not LOCAL_ADMIN_EMAIL or not LOCAL_ADMIN_PASSWORD:
        return
    existing = User.query.filter_by(email=LOCAL_ADMIN_EMAIL).first()
    if existing:
        changed = False
        if existing.role != "admin":
            existing.role = "admin"
            existing.role_source = "ADMIN"
            changed = True
        if existing.auth_type != "local":
            existing.auth_type = "local"
            changed = True
        if existing.password == "ad_auth_placeholder":
            existing.set_password(LOCAL_ADMIN_PASSWORD)
            changed = True
        # Opcional: travar para evitar sobrescrita no login AD
        if not existing.role_locked_by_admin:
            existing.role_locked_by_admin = True
            changed = True

        if changed:
            existing.updated_by_admin_at = datetime.utcnow()
            db.session.commit()
            logger.info("Admin local existente ajustado de acordo com .env")
        return

    admin = User(
        email=LOCAL_ADMIN_EMAIL,
        username=LOCAL_ADMIN_USERNAME or LOCAL_ADMIN_EMAIL.split("@")[0],
        role="admin",
        role_source="ADMIN",
        role_locked_by_admin=True,
        auth_type="local",
        password="ad_auth_placeholder"
    )
    admin.set_password(LOCAL_ADMIN_PASSWORD)
    db.session.add(admin)
    db.session.commit()
    logger.info("Admin local criado a partir do .env")


def _needs_profile_completion(user: User) -> bool:
    """Retorna True se aniversario ou sexo estiverem faltando."""
    if not user:
        return False
    missing_birthday = (user.aniversario is None)
    missing_sex = (user.sexo is None) or (str(user.sexo).strip() == "")
    return missing_birthday or missing_sex


# ---------- Guardião global: obriga completar perfil ----------
@auth_bp.before_app_request
def _enforce_profile_completion():
    """
    Se o usuário estiver logado e faltarem 'sexo' ou 'aniversario',
    bloqueia o acesso a todas as rotas, exceto:
    - auth.completar_perfil (a própria tela de completar)
    - auth.logout (permitir sair)
    - static (arquivos estáticos)
    Guarda também a rota alvo para retornar após completar.
    """
    if not current_user.is_authenticated:
        return
    if not _needs_profile_completion(current_user):
        return

    allowed_endpoints = {"auth.completar_perfil", "auth.logout", "static"}
    ep = (request.endpoint or "")
    if ep in allowed_endpoints:
        return

    # salva destino só uma vez
    if "next_endpoint" not in session:
        session["next_endpoint"] = ep
        session["next_view_args"] = request.view_args or {}
    flash("Complete seu perfil (sexo e aniversário) para continuar.", "warning")
    return redirect(url_for("auth.completar_perfil"))


# ---------------------- ROTAS ----------------------
@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        # Se já estiver autenticado, checa perfil antes de ir para a home
        if _needs_profile_completion(current_user):
            flash("Complete seu perfil (sexo e aniversário) para continuar.", "warning")
            return redirect(url_for("auth.completar_perfil"))
        return redirect(url_for("solicitacao.solicitacao"))

    # Garante admin local (se configurado)
    _ensure_local_admin_seed()

    if request.method == "POST":
        identifier = request.form.get("username")
        password = request.form.get("password")

        # 1) Tenta AD
        ad_user = authenticate_ad(identifier, password)
        if ad_user:
            email = ad_user.get("email")
            display_name = ad_user.get("display_name")
            ad_title = ad_user.get("title")
            ad_groups = ad_user.get("groups") or []

            user, created_now = _get_or_create_user(email=email, nome=display_name)
            if user == "INATIVO":
                return redirect(url_for("auth.login", erro=2))
            if not user:
                flash("Erro ao criar usuário local.", "danger")
                return redirect(url_for("auth.login", erro="email_nao_encontrado"))

            # Registrar 'últimos vistos' do AD
            try:
                user.ad_title_last_seen = ad_title
                user.ad_groups_last_seen = json.dumps(ad_groups, ensure_ascii=False)
                db.session.commit()
            except Exception as e:
                logger.warning(f"Falha ao salvar últimos dados do AD: {e}")

            # -------------------- REGRA DO PRIMEIRO ACESSO --------------------
            # Se é o 1º login e o título AD NÃO está na lista permitida,
            # força role = "user" e impede qualquer promoção automática agora.
            skip_role_mapping_this_login = False
            if created_now:
                t_up = (ad_title or "").strip().upper()
                if t_up not in FIRST_LOGIN_ALLOWED_TITLES:
                    if user.role != "user":
                        user.role = "user"
                        user.role_source = "AD"  # origem AD, porém forçada pela regra
                        db.session.commit()
                    skip_role_mapping_this_login = True
                    logger.info(f"[FIRST LOGIN RULE] {user.email} title='{t_up}' não permitido -> role='user'")
            # ------------------------------------------------------------------

            # 1) Tenta definir role a partir do AD (respeitando prioridade/trava do admin)
            mapped_role = None if skip_role_mapping_this_login else map_role_from_ad(ad_title, ad_groups)
            admin_has_priority = (getattr(user, "role_source", None) == "ADMIN")
            locked = getattr(user, "role_locked_by_admin", False)
            if ROLE_MAP_FORCE:
                admin_has_priority = False  # força AD a prevalecer

            logger.info(
                f"[LOGIN SYNC] email={user.email} title={ad_title} mapped_role={mapped_role} "
                f"locked={locked} admin_has_priority={admin_has_priority} created_now={created_now}"
            )

            if mapped_role and not locked and not admin_has_priority:
                if user.role != mapped_role:
                    old = user.role
                    user.role = mapped_role
                    user.role_source = "AD"
                    db.session.commit()
                    logger.info(f"Role de {user.email} atualizado de '{old}' para '{mapped_role}' via AD.")
            elif mapped_role and (locked or admin_has_priority):
                logger.info(
                    f"Role via AD '{mapped_role}' ignorado (locked={locked}, role_source={user.role_source}) para {user.email}."
                )

            # 2) Fallback para regras por Excel APENAS se
            # - permitido por ENV,
            # - não houver mapeamento AD,
            # - não estiver travado,
            # - não houver prioridade de ADMIN,
            # - não estivermos pulando por regra do 1º login
            if USE_EXCEL_FALLBACK and (not skip_role_mapping_this_login) and (not mapped_role) and (not locked) and (not admin_has_priority):
                from .models import ExcelData
                if hasattr(user, 'username') and user.username:
                    excel_registro = ExcelData.query.filter(
                        ExcelData.nome == user.username
                    ).first()
                    if excel_registro:
                        cargo = excel_registro.cargo_agrupado or excel_registro.cargo or ""
                        gerente_divisao = excel_registro.gerente_divisao or ""
                        gerente_imediato = excel_registro.gerente_imediato or ""
                        diretoria = excel_registro.diretoria or ""

                        logger.info(
                            f"[EXCEL FALLBACK] email={user.email} nome={user.username} "
                            f"cargo='{cargo}' diretoria='{diretoria}' gerente_divisao='{gerente_divisao}'"
                        )

                        # (Opcional) Se quiser evitar promoção a 'diretor' por planilha, comente este bloco.
                        if  "DIRETOR" in cargo.upper():
                            user.role = "diretor"
                        elif ("GERENTE" in cargo.upper() and "SENIOR" in cargo.upper()) or \
                             ("GERENTE" in cargo.upper() and "SR" in cargo.upper()) or \
                             ("GERENTE SR" in cargo.upper()) or \
                             ("GERENTE SENIOR" in cargo.upper()) or \
                             "GERENTE SENIOR" in gerente_imediato.upper():
                            user.role = "gerente senior"
                        elif "GERENTE" in cargo.upper() or \
                             "COORDENADOR" in cargo.upper() or \
                             "COORD." in cargo.upper() or \
                             ("GERENTE" in gerente_imediato.upper()):
                            user.role = "gerente"
                        elif "GESTOR" in cargo.upper() or \
                             ("SUPERVISOR" in cargo.upper()) or \
                             ("SUPERVISOR" in gerente_imediato.upper()):
                            user.role = "gestor"

                        user.role_source = "LOCAL"
                        db.session.commit()

            # Vincula gestor se existir (vindo do AD)
            manager = ad_user.get("manager")
            if manager and manager.get("email"):
                gestor_user, _ = _get_or_create_user(
                    email=manager["email"],
                    nome=manager.get("display_name")
                )
                # vincula e promove gestor, se necessário
                if isinstance(gestor_user, User):
                    if getattr(user, "gestor_id", None) != gestor_user.id:
                        user.gestor_id = gestor_user.id
                        db.session.commit()
                    if gestor_user.role not in ("admin", "gestor", "gerente", "diretor", "gerente senior"):
                        gestor_user.role = "gestor"
                        db.session.commit()

            # Faz login
            login_user(user)

            # Se o logado já tem subordinados, garanta role apropriado
            subordinados_count = User.query.filter_by(gestor_id=user.id).count()
            if subordinados_count > 0 and user.role not in ("admin", "gerente", "gestor", "diretor", "gerente senior"):
                # Se o usuário tem subordinados mas não tem um papel definido, definir como gestor
                user.role = "gestor"
                db.session.commit()
            elif subordinados_count > 0 and user.role == "user" and user.role not in ("admin", "gerente", "gestor", "diretor", "gerente senior"):
                user.role = "gestor"
                db.session.commit()

            _build_session(user)

            # Checagem de perfil
            if _needs_profile_completion(user):
                flash("Complete seu perfil (sexo e aniversário) para continuar.", "warning")
                return redirect(url_for("auth.completar_perfil"))

            flash(f"Bem-vindo, {display_name}!", "success")

            # Redirecionar de acordo com as novas regras:
            # - diretor e gerente senior: /visualizacao-gerencial
            # - gerente: /visualizacao-gerencial-gerente
            # - admin: acesso a tudo (dashboard admin)
            if user.role == "admin":
                return redirect(url_for("admin.dashboard"))
            elif user.role in ["diretor", "gerente senior"]:
                return redirect(url_for("excel_upload.visualizacao_gerencial"))
            elif user.role == "gerente":
                return redirect(url_for("excel_upload.visualizacao_gerencial_gerente"))
            else:
                return redirect(url_for("solicitacao.solicitacao"))

        # 2) Tenta autenticação local (usuários criados pelo admin)
        local_user = _authenticate_local_user(identifier, password)
        if local_user:
            login_user(local_user)

            # Se o logado já tem subordinados, garanta role apropriado
            subordinados_count = User.query.filter_by(gestor_id=local_user.id).count()
            if subordinados_count > 0 and local_user.role not in ("admin", "gerente", "gestor", "diretor", "gerente senior"):
                # Se o usuário tem subordinados mas não tem um papel definido, definir como gestor
                local_user.role = "gestor"
                db.session.commit()
            elif subordinados_count > 0 and local_user.role == "user" and local_user.role not in ("admin", "gerente", "gestor", "diretor", "gerente senior"):
                local_user.role = "gestor"
                db.session.commit()

            _build_session(local_user)

            if _needs_profile_completion(local_user):
                flash("Complete seu perfil (sexo e aniversário) para continuar.", "warning")
                return redirect(url_for("auth.completar_perfil"))

            flash(f"Bem-vindo (modo local), {local_user.username}!", "success")

            # Redirecionar de acordo com as novas regras
            if local_user.role == "admin":
                return redirect(url_for("admin.dashboard"))
            elif local_user.role in ["diretor", "gerente senior"]:
                return redirect(url_for("excel_upload.visualizacao_gerencial"))
            elif local_user.role == "gerente":
                return redirect(url_for("excel_upload.visualizacao_gerencial_gerente"))
            else:
                return redirect(url_for("solicitacao.solicitacao"))

        # Nenhum método autenticou
        return redirect(url_for("auth.login", erro=1))

    return render_template("login.html")


@auth_bp.route("/completar-perfil", methods=["GET", "POST"])
@login_required
def completar_perfil():
    """
    Tela simples para preencher 'sexo' (M/F) e 'aniversario' (yyyy-mm-dd).
    Se já estiver completo, redireciona à tela principal.
    """
    # Se já estiver tudo preenchido, não precisa ficar aqui
    if not _needs_profile_completion(current_user):
        return redirect(url_for("solicitacao.solicitacao"))

    if request.method == "POST":
        sexo = (request.form.get("sexo") or "").strip().upper()
        aniversario_str = (request.form.get("aniversario") or "").strip()

        # Validações simples
        errors = []
        if sexo not in ("M", "F"):
            errors.append("Informe o sexo como 'M' (Masculino) ou 'F' (Feminino).")

        from datetime import datetime as _dt
        try:
            if aniversario_str:
                aniversario_dt = _dt.strptime(aniversario_str, "%Y-%m-%d").date()
            else:
                errors.append("Informe a data de aniversário.")
                aniversario_dt = None
        except ValueError:
            errors.append("Data de aniversário inválida. Use o formato AAAA-MM-DD.")
            aniversario_dt = None

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("completar_perfil.html", user=current_user)

        # Persistir alterações
        current_user.sexo = sexo
        current_user.aniversario = aniversario_dt
        db.session.commit()

        flash("Perfil atualizado com sucesso!", "success")

        # Redireciona para a rota que tentou acessar originalmente
        next_ep = session.pop("next_endpoint", None)
        next_args = session.pop("next_view_args", {}) if next_ep else {}
        if next_ep:
            try:
                return redirect(url_for(next_ep, **next_args))
            except Exception:
                pass  # se falhar, cai no padrão

        return redirect(url_for("solicitacao.solicitacao"))

    return render_template("completar_perfil.html", user=current_user)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("usuario", None)
    flash("Você saiu do sistema com sucesso!", "success")
    return redirect(url_for("auth.login"))