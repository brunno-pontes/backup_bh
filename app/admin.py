from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from .models import User, Request, db
from functools import wraps
from werkzeug.security import generate_password_hash
from datetime import datetime  # <-- add

admin_bp = Blueprint("admin", __name__)

# Decorator para verificar se é administrador
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            flash("Acesso negado. Apenas administradores podem acessar esta área.", "danger")
            return redirect(url_for("auth.login"))
        return func(*args, **kwargs)
    return wrapper


@admin_bp.route("/admin")
@login_required
@admin_required
def dashboard():
    """Painel administrativo principal"""
    total_usuarios = User.query.count()
    admins = User.query.filter_by(role="admin").count()
    gerentes = User.query.filter_by(role="gerente").count()
    gestores = User.query.filter_by(role="gestor").count()
    focais = User.query.filter_by(role="focal").count()
    usuarios = User.query.filter_by(role="user").count()

    # Listar todos os usuários
    usuarios_lista = User.query.all()

    return render_template(
        "admin/dashboard.html",
        total_usuarios=total_usuarios,
        admins=admins,
        gerentes=gerentes,
        gestores=gestores,
        focais=focais,
        usuarios=usuarios,
        usuarios_lista=usuarios_lista
    )


@admin_bp.route("/admin/usuarios")
@login_required
@admin_required
def listar_usuarios():
    """Listar todos os usuários"""
    usuarios = User.query.all()
    gestores = User.query.filter_by(role='gestor').all()
    return render_template("admin/usuarios.html", usuarios=usuarios, gestores=gestores)


@admin_bp.route("/admin/usuarios/adicionar", methods=["GET"])
@login_required
@admin_required
def adicionar_usuario_form():
    """Formulário para adicionar novo usuário"""
    gestores = User.query.filter_by(role='gestor').all()
    return render_template("admin/adicionar_usuario.html", gestores=gestores)


@admin_bp.route("/admin/usuarios/adicionar", methods=["POST"])
@login_required
@admin_required
def adicionar_usuario():
    """Adicionar novo usuário"""
    email = request.form.get("email", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "user").strip()
    gestor_id = request.form.get("gestor_id", "").strip()
    lock_role = request.form.get("lock_role") in ("on", "true", "1")

    # Validar campos obrigatórios
    if not email or not username or not password:
        flash("Email, nome de usuário e senha são obrigatórios!", "danger")
        gestores = User.query.filter_by(role='gestor').all()
        return render_template("admin/adicionar_usuario.html", gestores=gestores)

    # Verificar se email já existe
    if User.query.filter_by(email=email).first():
        flash("Email já cadastrado!", "danger")
        gestores = User.query.filter_by(role='gestor').all()
        return render_template("admin/adicionar_usuario.html", gestores=gestores)

    # Verificar se username já existe
    if User.query.filter_by(username=username).first():
        flash("Nome de usuário já existe!", "danger")
        gestores = User.query.filter_by(role='gestor').all()
        return render_template("admin/adicionar_usuario.html", gestores=gestores)

    # Criar novo usuário
    novo_usuario = User(
        email=email.upper() if email else email,
        username=username.upper() if username else username,
        password=generate_password_hash(password),
        auth_type="local",  # Usuário criado localmente pelo admin
        role=role,
        role_source="ADMIN",
        role_locked_by_admin=lock_role,
    )
    if lock_role:
        novo_usuario.updated_by_admin_at = datetime.utcnow()

    # Definir gestor se fornecido
    if gestor_id:
        try:
            novo_usuario.gestor_id = int(gestor_id)
        except (ValueError, TypeError):
            pass

    try:
        db.session.add(novo_usuario)
        db.session.commit()
        flash(f"Usuário '{username}' adicionado com sucesso!", "success")
        return redirect(url_for("admin.listar_usuarios"))
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao adicionar usuário: {str(e)}", "danger")
        gestores = User.query.filter_by(role='gestor').all()
        return render_template("admin/adicionar_usuario.html", gestores=gestores)


@admin_bp.route("/admin/usuario/<int:user_id>/editar-perfil", methods=["POST"])
@login_required
@admin_required
def editar_perfil(user_id):
    """Alterar perfil de usuário"""
    usuario = User.query.get_or_404(user_id)
    novo_perfil = request.form.get("novo_perfil", "").strip()
    gestor_id = request.form.get("gestor_id", "").strip()
    lock_role = request.form.get("lock_role") in ("on", "true", "1")

    # Validar perfil
    perfis_validos = ["admin", "gerente", "gestor", "focal", "user", "gerente senior", "diretor"]
    if novo_perfil not in perfis_validos:
        flash("Perfil inválido!", "danger")
        return redirect(url_for("admin.listar_usuarios"))

    # Proteção: evitar que o próprio admin se remova do papel admin
    if usuario.id == current_user.id and novo_perfil != "admin":
        flash("Você não pode alterar seu próprio perfil de administrador.", "warning")
        return redirect(url_for("admin.listar_usuarios"))

    # Atualizar perfil + origem e auditoria
    usuario.role = novo_perfil
    usuario.role_source = "ADMIN"
    if lock_role:
        usuario.role_locked_by_admin = True
    usuario.updated_by_admin_at = datetime.utcnow()

    # Atualizar gestor
    if gestor_id:
        try:
            usuario.gestor_id = int(gestor_id)
        except (ValueError, TypeError):
            usuario.gestor_id = None
    else:
        usuario.gestor_id = None

    try:
        db.session.commit()
        flash(f"Perfil do usuário {usuario.username} alterado para {novo_perfil} com sucesso!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao atualizar perfil: {str(e)}", "danger")
    return redirect(url_for("admin.listar_usuarios"))


@admin_bp.route("/admin/usuario/<int:user_id>/mudar-gestor", methods=["GET", "POST"])
@login_required
@admin_required
def mudar_gestor(user_id):
    """Mudar o gestor de um usuário"""
    usuario = User.query.get_or_404(user_id)

    if request.method == "POST":
        novo_gestor_id = request.form.get("novo_gestor_id", "").strip()
        if novo_gestor_id:
            try:
                novo_gestor_id = int(novo_gestor_id)
                novo_gestor = User.query.get(novo_gestor_id)
                if novo_gestor and novo_gestor.role in ['admin', 'gestor']:
                    usuario.gestor_id = novo_gestor_id
                    db.session.commit()
                    flash(f"O gestor do usuário {usuario.username} foi alterado para {novo_gestor.username}.", "success")
                else:
                    flash("O novo gestor selecionado não é válido.", "danger")
            except (ValueError, TypeError):
                flash("ID do gestor inválido.", "danger")
        else:
            usuario.gestor_id = None
            db.session.commit()
            flash(f"O gestor do usuário {usuario.username} foi removido.", "success")
        return redirect(url_for("admin.listar_usuarios"))

    # GET: exibir formulário
    gestores = User.query.filter(User.role.in_(['admin', 'gestor'])).all()
    return render_template("admin/mudar_gestor.html", usuario=usuario, gestores=gestores)


@admin_bp.route("/admin/gestor/<int:gestor_id>/delegar", methods=["GET", "POST"])
@login_required
@admin_required
def delegar_gestao(gestor_id):
    """Delegar gestão para outro gestor na ausência do gestor principal"""
    gestor_principal = User.query.get_or_404(gestor_id)
    if gestor_principal.role not in ['admin', 'gestor']:
        flash("O usuário selecionado não é um gestor válido.", "danger")
        return redirect(url_for("admin.listar_usuarios"))

    if request.method == "POST":
        gestor_substituto_id = request.form.get("gestor_substituto_id", "").strip()
        if gestor_substituto_id:
            try:
                gestor_substituto_id = int(gestor_substituto_id)
                gestor_substituto = User.query.get(gestor_substituto_id)
                if gestor_substituto and gestor_substituto.role in ['admin', 'gestor'] and gestor_substituto_id != gestor_id:
                    # Atualizar o gestor_id dos subordinados do gestor principal para o substituto
                    subordinados = User.query.filter_by(gestor_id=gestor_principal.id).all()
                    for subordinado in subordinados:
                        subordinado.gestor_id = gestor_substituto.id
                    db.session.commit()
                    flash(f"A gestão do gestor {gestor_principal.username} foi delegada ao gestor {gestor_substituto.username}.", "success")
                else:
                    flash("O gestor substituto selecionado não é válido.", "danger")
            except (ValueError, TypeError):
                flash("ID do gestor substituto inválido.", "danger")
        else:
            # Se não for selecionado um substituto, voltar à gestão original
            flash("Selecione um gestor substituto.", "danger")
        return redirect(url_for("admin.listar_usuarios"))

    # GET: exibir formulário
    gestores = User.query.filter(
        User.role.in_(['admin', 'gestor']),
        User.id != gestor_principal.id
    ).all()
    return render_template("admin/delegar_gestao.html", gestor_principal=gestor_principal, gestores=gestores)


@admin_bp.route("/admin/usuario/<int:user_id>/remover", methods=["POST"])
@login_required
@admin_required
def remover_usuario(user_id):
    """Remover usuário"""
    usuario = User.query.get_or_404(user_id)

    # Proteção: não permitir remover o próprio admin
    if usuario.id == current_user.id:
        flash("Você não pode remover a si mesmo!", "danger")
        return redirect(url_for("admin.listar_usuarios"))

    # Proteção: não permitir remover outros admins (opcional)
    # Se quiser permitir, comente as próximas 3 linhas
    if usuario.role == "admin":
        flash("Não é possível remover outros administradores!", "danger")
        return redirect(url_for("admin.listar_usuarios"))

    try:
        # Remover solicitações do usuário primeiro
        Request.query.filter_by(user_id=user_id).delete()
        # Remover usuário
        db.session.delete(usuario)
        db.session.commit()
        flash(f"Usuário '{usuario.username}' removido com sucesso!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao remover usuário: {str(e)}", "danger")

    return redirect(url_for("admin.listar_usuarios"))


@admin_bp.route('/admin/usuarios/editar-massa', methods=['POST'])
@login_required
@admin_required
def editar_usuarios_massa():
    """Editar múltiplos usuários em massa"""
    # Obter dados do formulário
    usuarios_selecionados = request.form.getlist('usuarios_selecionados')
    novo_perfil = request.form.get('novo_perfil', '').strip()
    novo_gestor_id = request.form.get('novo_gestor_id', '').strip()
    lock_role = request.form.get("lock_role") in ("on", "true", "1")

    # Validar entrada
    if not usuarios_selecionados:
        flash('Selecione pelo menos um usuário para editar.', 'danger')
        return redirect(url_for('admin.listar_usuarios'))
    if not novo_perfil:
        flash('Selecione um novo perfil.', 'danger')
        return redirect(url_for('admin.listar_usuarios'))

    # Validar perfil
    perfis_validos = ['admin', 'gerente', 'gestor', 'focal', 'user', 'gerente senior', 'diretor']
    if novo_perfil not in perfis_validos:
        flash('Perfil inválido!', 'danger')
        return redirect(url_for('admin.listar_usuarios'))

    # Validar gestor (se fornecido)
    gestor = None
    if novo_gestor_id:
        try:
            gestor_id = int(novo_gestor_id)
            gestor = User.query.get(gestor_id)
            if not gestor:
                flash('Gestor selecionado não encontrado.', 'danger')
                return redirect(url_for('admin.listar_usuarios'))
        except (ValueError, TypeError):
            flash('ID do gestor inválido.', 'danger')
            return redirect(url_for('admin.listar_usuarios'))

    # Processar usuários selecionados
    usuarios_atualizados = 0
    for user_id_str in usuarios_selecionados:
        try:
            user_id = int(user_id_str)
            usuario = User.query.get(user_id)
            if usuario:
                # Não permitir que o admin mude o próprio perfil para algo diferente de admin
                if usuario.id == current_user.id and novo_perfil != 'admin':
                    flash(f'Não é possível alterar seu próprio perfil de administrador.', 'warning')
                    continue

                # Atualizar perfil + metadados
                usuario.role = novo_perfil
                usuario.role_source = "ADMIN"
                if lock_role:
                    usuario.role_locked_by_admin = True
                usuario.updated_by_admin_at = datetime.utcnow()

                # Atualizar gestor (se fornecido)
                if gestor:
                    usuario.gestor_id = gestor.id
                elif novo_gestor_id == '':
                    # Remover gestor se '' (nenhum)
                    usuario.gestor_id = None

                usuarios_atualizados += 1
        except (ValueError, TypeError):
            continue

    try:
        db.session.commit()
        flash(f'{usuarios_atualizados} usuários atualizados com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao atualizar usuários: {str(e)}', 'danger')

    return redirect(url_for('admin.listar_usuarios'))
