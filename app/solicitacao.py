from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime, date
from .models import Request, User, db

solicitacao_bp = Blueprint("solicitacao", __name__)


@solicitacao_bp.route("/solicitacao", methods=["GET", "POST"])
@login_required
def solicitacao():
    if request.method == "GET":
        # Buscar usuários comuns para o dropdown (apenas se for focal)
        usuarios_comuns = []
        if current_user.role == "focal":
            # (role == 'user') OU (é o próprio focal), e do mesmo gestor
            usuarios_comuns = User.query.filter(
                (User.role == "user") | (User.id == current_user.id),
                User.gestor_id == current_user.gestor_id
            ).all()
        return render_template("solicitacao.html", usuarios_comuns=usuarios_comuns)

    # POST
    tipo = request.form.get("tipo")
    inicio_str = request.form.get("inicio")
    fim_str = request.form.get("fim")

    # Validar datas
    try:
        inicio = datetime.strptime(inicio_str, "%Y-%m-%d").date()
        fim = datetime.strptime(fim_str, "%Y-%m-%d").date()
    except ValueError:
        flash("Formato de data inválido!", "danger")
        return redirect(url_for("solicitacao.solicitacao"))

    # Determinar para qual usuário criar a solicitação
    if current_user.role == "focal":
        # Se for focal, pode criar para si ou para um usuário comum da sua equipe
        user_id_str = request.form.get("user_id")
        if not user_id_str:
            user_id = current_user.id
        else:
            try:
                user_id = int(user_id_str)
                # Verificar se pertence à equipe do focal (e é 'user' ou o próprio focal)
                usuario_destino = User.query.filter(
                    (User.id == user_id),
                    ((User.role == "user") | (User.id == current_user.id)),
                    User.gestor_id == current_user.gestor_id
                ).first()
                if not usuario_destino:
                    flash("Usuário inválido ou não pertence à sua equipe!", "danger")
                    usuarios_comuns = User.query.filter(
                        (User.role == "user") | (User.id == current_user.id),
                        User.gestor_id == current_user.gestor_id
                    ).all()
                    return render_template("solicitacao.html", usuarios_comuns=usuarios_comuns)
                user_id = usuario_destino.id
            except (ValueError, TypeError):
                flash("Usuário inválido!", "danger")
                usuarios_comuns = User.query.filter(
                    (User.role == "user") | (User.id == current_user.id),
                    User.gestor_id == current_user.gestor_id
                ).all()
                return render_template("solicitacao.html", usuarios_comuns=usuarios_comuns)
    else:
        # Usuário comum: usa ele mesmo
        user_id = current_user.id

    # Verificação especial para férias - limite de 30 dias/ano
    if tipo == "Ferias":
        ferias_ano_atual = Request.query.filter(
            Request.user_id == user_id,
            Request.type == "Ferias",
            Request.start_date >= date(inicio.year, 1, 1),
            Request.start_date <= date(inicio.year, 12, 31)
        ).all()
        total_dias_solicitados = sum(
            (f.end_date - f.start_date).days + 1
            for f in ferias_ano_atual
            if f.status in ["Aprovado", "Pendente"]
        )
        novos_dias = (fim - inicio).days + 1
        if total_dias_solicitados + novos_dias > 30:
            flash(
                f"Este usuário já tem {total_dias_solicitados} dias de férias solicitados. "
                "Com esta solicitação, ultrapassaria o limite de 30 dias por ano.",
                "danger"
            )
            usuarios_comuns = []
            if current_user.role == "focal":
                usuarios_comuns = User.query.filter(
                    (User.role == "user") | (User.id == current_user.id),
                    User.gestor_id == current_user.gestor_id
                ).all()
            return render_template("solicitacao.html", usuarios_comuns=usuarios_comuns)

    # Criar nova solicitação
    new_request = Request(
        user_id=user_id,
        type=tipo,
        start_date=inicio,
        end_date=fim
    )
    errors = new_request.validate()
    if errors:
        for e in errors:
            flash(e, "danger")
    else:
        try:
            db.session.add(new_request)
            db.session.commit()
            flash("Solicitação registrada com sucesso!", "success")
            return redirect(url_for("requests.minhas_solicitacoes"))
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao registrar solicitação: {str(e)}", "danger")

    # Recarregar em caso de erro
    usuarios_comuns = []
    if current_user.role == "focal":
        usuarios_comuns = User.query.filter(
            (User.role == "user") | (User.id == current_user.id),
            User.gestor_id == current_user.gestor_id
        ).all()
    return render_template("solicitacao.html", usuarios_comuns=usuarios_comuns)
