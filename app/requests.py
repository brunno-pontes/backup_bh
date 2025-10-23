from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from .models import Request, User
from datetime import date

requests_bp = Blueprint("requests", __name__)


@requests_bp.route("/minhas-solicitacoes")
@login_required
def minhas_solicitacoes():
    requests_list = Request.query.filter_by(user_id=current_user.id).all()

    # Calcular total de dias de férias solicitados no ano atual
    ano_atual = date.today().year
    ferias_ano_atual = Request.query.filter(
        Request.user_id == current_user.id,
        Request.type == "Ferias",
        Request.start_date >= date(ano_atual, 1, 1),
        Request.start_date <= date(ano_atual, 12, 31)
    ).all()
    total_dias_ferias = sum(
        (f.end_date - f.start_date).days + 1
        for f in ferias_ano_atual
        if f.status in ["Aprovado", "Pendente"]
    )

    return render_template("minhas_solicitacoes.html", requests=requests_list, total_dias_ferias=total_dias_ferias)


@requests_bp.route("/solicitacoes-equipe")
@login_required
def solicitacoes_equipe():
    """Lista as solicitações de acordo com o papel do usuário:
    - Gestor/Admin (is_gestor=True): todas as solicitações dos subordinados
    - Usuário comum: apenas solicitações Aprovadas dos colegas da mesma equipe (exclui as próprias)
    Suporta filtros opcionais ?status= e ?tipo= e ordena por start_date desc.
    """

    # Base query conforme papel
    if getattr(current_user, "is_gestor", False):
        subordinados_ids = [sub.id for sub in current_user.subordinados]
        query = Request.query.filter(Request.user_id.in_(subordinados_ids))
    else:
        if current_user.gestor_id:
            colegas_ids = [u.id for u in User.query.filter_by(gestor_id=current_user.gestor_id).all()]
            query = Request.query.filter(
                Request.user_id.in_(colegas_ids),
                Request.user_id != current_user.id,
                Request.status == "Aprovado"
            )
        else:
            # Sem gestor vinculado -> lista vazia
            query = Request.query.filter(Request.user_id == -1)

    # Filtros opcionais
    status_filtro = request.args.get('status', '').strip()
    tipo_filtro = request.args.get('tipo', '').strip()

    # status: só faz sentido expor para gestores (mas manteremos se passado por URL)
    if status_filtro:
        query = query.filter(Request.status == status_filtro)
    if tipo_filtro:
        query = query.filter(Request.type == tipo_filtro)

    todas_solicitacoes = query.order_by(Request.start_date.desc()).all()

    # Opções para filtros (com base no resultado atual)
    tipos_disponiveis = sorted({r.type for r in todas_solicitacoes})
    status_disponiveis = sorted({r.status for r in todas_solicitacoes})

    return render_template(
        "solicitacoes_equipe.html",
        solicitacoes=todas_solicitacoes,
        status_filtro=status_filtro,
        tipo_filtro=tipo_filtro,
        tipos_disponiveis=tipos_disponiveis,
        status_disponiveis=status_disponiveis
    )
