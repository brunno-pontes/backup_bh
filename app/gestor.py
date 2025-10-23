from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, Response
from flask_login import login_required, current_user
from datetime import datetime, date
from .models import Request, User, db
from sqlalchemy import func
from werkzeug.security import generate_password_hash
import pandas as pd
import openpyxl


gestor_bp = Blueprint("gestor", __name__)

# decorator para verificar se é gestor ou gerente
def gestor_required(func):
    from functools import wraps
    from flask import abort
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Permitir acesso a usuários com papel "gestor" ou "gerente"
        if current_user.role not in ("gestor", "gerente"):
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    return wrapper


@gestor_bp.route("/gestor/solicitacoes")
@login_required
@gestor_required
def lista_solicitacoes():
    # Obter subordinados do gerente atual
    subordinados_ids = [sub.id for sub in current_user.subordinados]
    
    # Filtrar solicitações apenas dos subordinados
    requests = Request.query.filter(
        Request.user_id.in_(subordinados_ids),
        Request.status == "Pendente"
    ).all()
    
    # Filtrar por tipo se especificado
    tipo_selecionado = request.args.get('tipo')
    if tipo_selecionado:
        requests = [r for r in requests if r.type == tipo_selecionado]
    
    return render_template("gestor_solicitacoes.html", requests=requests, tipo_selecionado=tipo_selecionado)


@gestor_bp.route("/gestor/solicitacoes/<int:request_id>/<acao>")
@login_required
@gestor_required
def aprovar_reprovar(request_id, acao):
    # CORREÇÃO: Remover espaços da ação
    acao = acao.strip()
    
    # Verificar se a solicitação pertence a um subordinado
    subordinados_ids = [sub.id for sub in current_user.subordinados]
    r = Request.query.filter(
        Request.id == request_id,
        Request.user_id.in_(subordinados_ids)
    ).first_or_404()
    
    # Verificar conflitos de datas antes de aprovar
    if acao == "aprovar":
        # Obter todas as solicitações aprovadas dos subordinados
        solicitacoes_aprovadas = Request.query.filter(
            Request.user_id.in_(subordinados_ids),
            Request.status == "Aprovado",
            Request.id != request_id  # Excluir a própria solicitação
        ).all()
        
        # Verificar se há conflito de datas
        conflitos = []
        for sol in solicitacoes_aprovadas:
            # Verificar se há sobreposição de datas
            if not (r.end_date < sol.start_date or r.start_date > sol.end_date):
                conflitos.append({
                    'usuario': sol.user.username,
                    'tipo': sol.type,
                    'periodo': f"{sol.start_date.strftime('%d/%m/%Y')} - {sol.end_date.strftime('%d/%m/%Y')}"
                })
        
        # Se houver conflitos, armazenar na sessão para mostrar no template
        if conflitos:
            from flask import session
            session['conflitos_solicitacao'] = {
                'request_id': request_id,
                'acao': acao,
                'conflitos': conflitos,
                'solicitacao': {
                    'usuario': r.user.username,
                    'tipo': r.type,
                    'periodo': f"{r.start_date.strftime('%d/%m/%Y')} - {r.end_date.strftime('%d/%m/%Y')}"
                }
            }
            return redirect(url_for("gestor.confirmar_aprovacao", request_id=request_id))
    
    # Processar ação normalmente se não houver conflitos ou se for reprovar
    if acao == "aprovar":
        r.status = "Aprovado"
    elif acao == "reprovar":
        r.status = "Rejeitado"
    else:
        flash("Ação inválida", "danger")
        return redirect(url_for("gestor.lista_solicitacoes"))

    db.session.commit()
    flash(f"Solicitação {acao} com sucesso!", "success")
    return redirect(url_for("gestor.lista_solicitacoes"))


@gestor_bp.route("/gestor/solicitacoes/<int:request_id>/confirmar")
@login_required
@gestor_required
def confirmar_aprovacao(request_id):
    from flask import session
    # Verificar se há conflitos armazenados na sessão
    if 'conflitos_solicitacao' not in session or session['conflitos_solicitacao']['request_id'] != request_id:
        flash("Nenhuma confirmação pendente encontrada", "warning")
        return redirect(url_for("gestor.lista_solicitacoes"))
    
    conflitos_data = session['conflitos_solicitacao']
    return render_template("gestor_confirmar_aprovacao.html", conflitos_data=conflitos_data)


@gestor_bp.route("/gestor/solicitacoes/<int:request_id>/confirmar/<acao>", methods=["POST"])
@login_required
@gestor_required
def processar_confirmacao(request_id, acao):
    from flask import session
    
    # Verificar se há conflitos armazenados na sessão
    if 'conflitos_solicitacao' not in session or session['conflitos_solicitacao']['request_id'] != request_id:
        flash("Nenhuma confirmação pendente encontrada", "warning")
        return redirect(url_for("gestor.lista_solicitacoes"))
    
    # Obter dados da sessão
    conflitos_data = session['conflitos_solicitacao']
    
    # Verificar se a solicitação pertence a um subordinado
    subordinados_ids = [sub.id for sub in current_user.subordinados]
    r = Request.query.filter(
        Request.id == request_id,
        Request.user_id.in_(subordinados_ids)
    ).first_or_404()
    
    if acao == "aprovar":
        r.status = "Aprovado"
        flash("Solicitação aprovada com sucesso! Conflitos de datas foram ignorados.", "warning")
    elif acao == "reprovar":
        r.status = "Rejeitado"
        flash("Solicitação reprovada.", "success")
    else:
        flash("Ação inválida", "danger")
        return redirect(url_for("gestor.lista_solicitacoes"))

    db.session.commit()
    
    # Limpar dados da sessão
    session.pop('conflitos_solicitacao', None)
    
    return redirect(url_for("gestor.lista_solicitacoes"))


@gestor_bp.route("/gestor/relatorios")
@login_required
@gestor_required
def relatorios():
    # CORREÇÃO: Corrigir status inválidos no banco de dados
    solicitacoes_invalidas = Request.query.filter(Request.status == "A provado").all()
    for s in solicitacoes_invalidas:
        s.status = "Aprovado"
    if solicitacoes_invalidas:
        db.session.commit()
    
    # Obter subordinados do gestor atual
    subordinados = current_user.subordinados
    subordinados_ids = [sub.id for sub in subordinados]
    
    # Obter todas as solicitações dos subordinados
    todas_solicitacoes = Request.query.filter(
        Request.user_id.in_(subordinados_ids)
    ).all()
    
    # Contar solicitações por status
    pendentes = len([r for r in todas_solicitacoes if r.status == "Pendente"])
    aprovadas = len([r for r in todas_solicitacoes if r.status == "Aprovado"])
    rejeitadas = len([r for r in todas_solicitacoes if r.status == "Rejeitado"])
    
    # Contar solicitações por tipo
    tipos = {}
    for r in todas_solicitacoes:
        if r.type in tipos:
            tipos[r.type] += 1
        else:
            tipos[r.type] = 1
    
    # Solicitações por mês (últimos 12 meses)
    hoje = date.today()
    ano_atual = hoje.year
    mes_atual = hoje.month
    
    # Criar lista de meses para os últimos 12 meses
    meses_labels = []
    meses_data = []
    
    for i in range(12):
        # Calcular o mês/ano retroativamente
        mes = mes_atual - i
        ano = ano_atual
        if mes <= 0:
            mes += 12
            ano -= 1
            
        meses_labels.insert(0, f"{mes:02d}/{ano}")
        
        # Contar solicitações para este mês
        count = 0
        for r in todas_solicitacoes:
            if r.start_date.month == mes and r.start_date.year == ano:
                count += 1
        meses_data.insert(0, count)
    
    # Solicitações por tipo e status
    tipos_status = {}
    for tipo in ['Ferias', 'BH', 'Dayoff', 'Maternidade', 'Paternidade']:
        tipos_status[tipo] = {
            'Pendente': 0,
            'Aprovado': 0,
            'Rejeitado': 0
        }
    
    for r in todas_solicitacoes:
        if r.type in tipos_status:
            tipos_status[r.type][r.status] += 1
    
    # Dias de férias concedidos por usuário
    ferias_por_usuario = {}
    for sub in subordinados:
        ferias = Request.query.filter(
            Request.user_id == sub.id,
            Request.type == 'Ferias',
            Request.status == 'Aprovado'
        ).all()
        
        total_dias = 0
        for f in ferias:
            total_dias += (f.end_date - f.start_date).days + 1
            
        ferias_por_usuario[sub.username] = total_dias
    
    return render_template("gestor_relatorios.html", 
                         subordinados=subordinados,
                         pendentes=pendentes,
                         aprovadas=aprovadas,
                         rejeitadas=rejeitadas,
                         tipos=tipos,
                         meses_labels=meses_labels,
                         meses_data=meses_data,
                         tipos_status=tipos_status,
                         ferias_por_usuario=ferias_por_usuario)


@gestor_bp.route("/gestor/relatorios/detalhes")
@login_required
@gestor_required
def relatorios_detalhes():
    # Obter subordinados do gestor atual
    subordinados_ids = [sub.id for sub in current_user.subordinados]
    
    # Filtros
    status_filtro = request.args.get('status', '')
    tipo_filtro = request.args.get('tipo', '')
    data_inicio = request.args.get('data_inicio', '')
    data_fim = request.args.get('data_fim', '')
    
    # Query base
    query = Request.query.filter(Request.user_id.in_(subordinados_ids))
    
    # Aplicar filtros
    if status_filtro:
        query = query.filter(Request.status == status_filtro)
    
    if tipo_filtro:
        query = query.filter(Request.type == tipo_filtro)
    
    if data_inicio:
        data_inicio_obj = datetime.strptime(data_inicio, '%Y-%m-%d').date()
        query = query.filter(Request.start_date >= data_inicio_obj)
    
    if data_fim:
        data_fim_obj = datetime.strptime(data_fim, '%Y-%m-%d').date()
        query = query.filter(Request.end_date <= data_fim_obj)
    
    solicitacoes = query.all()
    
    # Tipos disponíveis para filtro
    tipos_disponiveis = ['Ferias', 'BH', 'Dayoff', 'Maternidade', 'Paternidade']
    status_disponiveis = ['Pendente', 'Aprovado', 'Rejeitado']
    
    return render_template("gestor_relatorios_detalhes.html",
                         solicitacoes=solicitacoes,
                         tipos_disponiveis=tipos_disponiveis,
                         status_disponiveis=status_disponiveis,
                         status_filtro=status_filtro,
                         tipo_filtro=tipo_filtro,
                         data_inicio=data_inicio,
                         data_fim=data_fim)


@gestor_bp.route("/gestor/subordinados")
@login_required
@gestor_required
def lista_subordinados():
    subordinados = current_user.subordinados
    return render_template("gestor_subordinados.html", subordinados=subordinados)


@gestor_bp.route("/gestor/subordinados/adicionar", methods=["GET", "POST"])
@login_required
@gestor_required
def adicionar_subordinado():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        sexo = request.form.get("sexo", "").strip()
        aniversario_str = request.form.get("aniversario", "").strip()
        role = request.form.get("role", "user").strip()
        
        # Validar campos obrigatórios
        if not email or not username or not password:
            flash("Email, nome de usuário e senha são obrigatórios!", "danger")
            return render_template("gestor_adicionar_subordinado.html")
        
    
        
        # Verificar se o email já existe
        if User.query.filter_by(email=email).first():
            flash("Email já cadastrado!", "danger")
            return render_template("gestor_adicionar_subordinado.html")
        
        # Verificar se o username já existe
        if User.query.filter_by(username=username).first():
            flash("Nome de usuário já existe!", "danger")
            return render_template("gestor_adicionar_subordinado.html")
        
        # Converter data de aniversário
        aniversario = None
        if aniversario_str:
            try:
                aniversario = datetime.strptime(aniversario_str, "%Y-%m-%d").date()
            except ValueError:
                flash("Data de aniversário inválida!", "danger")
                return render_template("gestor_adicionar_subordinado.html")
        
        # Criar novo usuário
        novo_usuario = User(
            email=email.upper() if email else email,
            username=username.upper() if username else username,
            password=generate_password_hash(password),
            role=role,
            gestor_id=current_user.id,
            aniversario=aniversario,
            sexo=sexo.upper() if sexo else sexo
        )
        
        try:
            db.session.add(novo_usuario)
            db.session.commit()
            flash(f"Subordinado '{username}' adicionado com sucesso!", "success")
            return redirect(url_for("gestor.lista_subordinados"))
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao adicionar subordinado: {str(e)}", "danger")
    
    return render_template("gestor_adicionar_subordinado.html")


@gestor_bp.route("/gestor/subordinados/<int:user_id>/editar", methods=["GET", "POST"])
@login_required
@gestor_required
def editar_subordinado(user_id):
    # Verificar se o usuário é subordinado do gestor atual
    subordinado = User.query.filter_by(id=user_id, gestor_id=current_user.id).first_or_404()
    
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        sexo = request.form.get("sexo")
        aniversario_str = request.form.get("aniversario")
        password = request.form.get("password")
        role = request.form.get("role")
        
        # Verificar se o email já existe (exceto para o próprio usuário)
        usuario_existente = User.query.filter(User.email == email, User.id != user_id).first()
        if usuario_existente:
            flash("Email já cadastrado!", "danger")
            return render_template("gestor_editar_subordinado.html", subordinado=subordinado)
        
        # Verificar se o nome de usuário já existe (exceto para o próprio usuário)
        usuario_existente = User.query.filter(User.username == username, User.id != user_id).first()
        if usuario_existente:
            flash("Nome de usuário já existe!", "danger")
            return render_template("gestor_editar_subordinado.html", subordinado=subordinado)
        
        # Atualizar dados
        subordinado.email = email.upper() if email else email
        subordinado.username = username.upper() if username else username
        subordinado.sexo = sexo.upper() if sexo else sexo
        subordinado.role = role
        
        # Converter data de aniversário
        if aniversario_str:
            try:
                subordinado.aniversario = datetime.strptime(aniversario_str, "%Y-%m-%d").date()
            except ValueError:
                flash("Data de aniversário inválida!", "danger")
                return render_template("gestor_editar_subordinado.html", subordinado=subordinado)
        else:
            subordinado.aniversario = None
        
        # Atualizar senha se fornecida
        if password:
            subordinado.password = generate_password_hash(password)
        
        try:
            db.session.commit()
            flash(f"Subordinado '{username}' atualizado com sucesso!", "success")
            return redirect(url_for("gestor.lista_subordinados"))
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao atualizar subordinado: {str(e)}", "danger")
    
    return render_template("gestor_editar_subordinado.html", subordinado=subordinado)


@gestor_bp.route("/gestor/subordinados/<int:user_id>/remover", methods=["POST"])
@login_required
@gestor_required
def remover_subordinado(user_id):
    # Verificar se o usuário é subordinado do gestor atual
    subordinado = User.query.filter_by(id=user_id, gestor_id=current_user.id).first_or_404()
    
    try:
        # Remover solicitações do subordinado
        Request.query.filter_by(user_id=user_id).delete()
        # Remover o subordinado
        db.session.delete(subordinado)
        db.session.commit()
        flash(f"Subordinado '{subordinado.username}' removido com sucesso!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao remover subordinado: {str(e)}", "danger")
    
    return redirect(url_for("gestor.lista_subordinados"))


@gestor_bp.route("/gestor/api/estatisticas")
@login_required
@gestor_required
def api_estatisticas():
    # Obter subordinados do gestor atual
    subordinados_ids = [sub.id for sub in current_user.subordinados]
    
    # Estatísticas básicas
    total_solicitacoes = Request.query.filter(Request.user_id.in_(subordinados_ids)).count()
    pendentes = Request.query.filter(Request.user_id.in_(subordinados_ids), Request.status == 'Pendente').count()
    aprovadas = Request.query.filter(Request.user_id.in_(subordinados_ids), Request.status == 'Aprovado').count()
    rejeitadas = Request.query.filter(Request.user_id.in_(subordinados_ids), Request.status == 'Rejeitado').count()
    
    # Solicitações por tipo
    tipos = db.session.query(Request.type, func.count(Request.id)).filter(
        Request.user_id.in_(subordinados_ids)
    ).group_by(Request.type).all()
    
    tipos_dict = {tipo: count for tipo, count in tipos}
    
    return jsonify({
        'total': total_solicitacoes,
        'pendentes': pendentes,
        'aprovadas': aprovadas,
        'rejeitadas': rejeitadas,
        'tipos': tipos_dict
    })


@gestor_bp.route("/gestor/exportar_solicitacoes")
@login_required
@gestor_required
def exportar_solicitacoes():
    try:
        # Importar pandas apenas quando necessário
        import pandas as pd
        from io import BytesIO
        
        # Obter subordinados do gestor atual
        subordinados_ids = [sub.id for sub in current_user.subordinados]
        
        # Obter todas as solicitações dos subordinados
        solicitacoes = Request.query.filter(
            Request.user_id.in_(subordinados_ids)
        ).all()
        
        # Preparar os dados para o DataFrame
        dados = []
        for r in solicitacoes:
            dados.append({
                'Usuário': r.user.username,
                'Tipo': r.type,
                'Data Início': r.start_date.strftime('%d/%m/%Y'),
                'Data Fim': r.end_date.strftime('%d/%m/%Y'),
                'Dias': (r.end_date - r.start_date).days + 1,
                'Status': r.status,
                'Data Solicitação': r.start_date.strftime('%d/%m/%Y')
            })
        
        # Criar DataFrame
        df = pd.DataFrame(dados)
        
        # Criar buffer para o arquivo Excel
        output = BytesIO()
        
        # Exportar para Excel
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Solicitações', index=False)
            
            # Formatar as colunas
            worksheet = writer.sheets['Solicitações']
            for column in worksheet.columns:
                worksheet.column_dimensions[column[0].column_letter].width = 15
        
        # Preparar a resposta
        output.seek(0)
        
        from flask import Response
        response = Response(
            output.getvalue(),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': 'attachment; filename="solicitacoes.xlsx"'
            }
        )
        
        return response
        
    except ImportError:
        # Fallback para CSV se pandas não estiver disponível
        import csv
        import io
        
        # Obter subordinados do gestor atual
        subordinados_ids = [sub.id for sub in current_user.subordinados]
        
        # Obter todas as solicitações dos subordinados
        solicitacoes = Request.query.filter(
            Request.user_id.in_(subordinados_ids)
        ).all()
        
        # Criar um arquivo CSV com as solicitações
        output = io.StringIO()
        writer = csv.writer(output, delimiter=';')
        
        # Escrever cabeçalho
        writer.writerow(['Usuário', 'Tipo', 'Data Início', 'Data Fim', 'Dias', 'Status', 'Data Solicitação'])
        
        # Escrever cada solicitação
        for r in solicitacoes:
            writer.writerow([
                r.user.username,
                r.type,
                r.start_date.strftime('%d/%m/%Y'),
                r.end_date.strftime('%d/%m/%Y'),
                (r.end_date - r.start_date).days + 1,
                r.status,
                r.start_date.strftime('%d/%m/%Y')
            ])
        
        # Converter para bytes
        csv_data = output.getvalue()
        output.close()
        csv_bytes = csv_data.encode('utf-8')
        
        from flask import Response
        response = Response(
            csv_bytes,
            mimetype='text/csv',
            headers={
                'Content-Disposition': 'attachment; filename="solicitacoes.csv"',
                'Content-Type': 'text/csv; charset=utf-8'
            }
        )
        
        return response