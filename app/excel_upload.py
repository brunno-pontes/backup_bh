from flask import Blueprint, render_template, request, flash, redirect, url_for, abort, Response
from flask_login import login_required, current_user
from .models import ExcelData, db, Request, User
import pandas as pd
from datetime import datetime, timedelta, date
from functools import wraps
import io
import unicodedata

excel_upload_bp = Blueprint("excel_upload", __name__)

# ==========================
#   AUTORIZAÇÃO / DECORATORS
# ==========================

def excel_upload_required(func):
    """Apenas admin, focal e gestor podem fazer upload de planilha"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.role not in ["admin", "focal", "gestor"]:
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    return wrapper


def visao_gerencial_required(func):
    """Apenas admin, diretor, gerente senior e focal podem acessar a visão gerencial"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.role not in ["admin", "diretor", "gerente senior", "focal"]:
            flash("Acesso negado. Apenas administradores, diretores, gerentes seniores e focais podem acessar esta funcionalidade.", "danger")
            return redirect(url_for('solicitacao.solicitacao'))
        return func(*args, **kwargs)
    return wrapper


def visao_gerencial_gerente_required(func):
    """Apenas admin, gerente e gestor podem acessar a visão gerencial de gerente"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.role not in ["admin", "gerente", "gestor"]:
            flash("Acesso negado. Apenas administradores, gerentes e gestores podem acessar esta funcionalidade.", "danger")
            return redirect(url_for('solicitacao.solicitacao'))
        return func(*args, **kwargs)
    return wrapper


# ==========================
#   HELPERS / PARSERS
# ==========================

def _norm_txt(s: str) -> str:
    """Upper + remove acentos para comparação robusta."""
    if not s:
        return ""
    s_up = s.upper()
    s_norm = unicodedata.normalize('NFKD', s_up)
    return "".join(c for c in s_norm if not unicodedata.combining(c))


def _bucket_por_evento(evento: str) -> str | None:
    """
    Classifica faixas APENAS para eventos de 'HORAS A VENCER ... BH':

    - 'HORAS A VENCER NO MÊS BH' | '1 MÊS' -> 'ate_30'
    - 'HORAS A VENCER 2 MESES BH'         -> 'de_31_60'
    - 'HORAS A VENCER 3 MESES BH'         -> 'de_61_90'
    - 'HORAS A VENCER 4+ MESES BH'        -> 'acima_120'

    Retorna None se não for um desses eventos.
    """
    ev = _norm_txt(evento)
    if "HORAS A VENCER" not in ev:
        return None

    if "NO MES" in ev or "1 MES" in ev:
        return "ate_30"
    if "2 MES" in ev:
        return "de_31_60"
    if "3 MES" in ev:
        return "de_61_90"
    if any(x in ev for x in ["4 MES", "5 MES", "6 MES", "7 MES", "8 MES", "9 MES", "10 MES", "11 MES", "12 MES"]):
        return "acima_120"

    # Se cair aqui, é um texto não mapeado -> não classifica
    return None


def _get_value_by_possible_names(df, row, possible_names):
    """Busca o primeiro nome de coluna compatível (normalizando acentos e underscores)."""
    def _norm_col_name(s: str) -> str:
        s = _norm_txt(s)
        return s.replace(' ', '_')
    for name in possible_names:
        norm_target = _norm_col_name(name)
        for col in df.columns:
            if _norm_col_name(col) == norm_target:
                val = row[col]
                return str(val) if pd.notna(val) else None
    return None


def _to_upper_if_string(value):
    return value.upper() if value and isinstance(value, str) else value


# ==========================
#   ROTAS
# ==========================

@excel_upload_bp.route("/excel-upload", methods=["GET", "POST"])
@login_required
@excel_upload_required
def upload_excel():
    if request.method == "POST":
        if 'file' not in request.files:
            flash("Nenhum arquivo selecionado!", "danger")
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash("Nenhum arquivo selecionado!", "danger")
            return redirect(request.url)

        if not file.filename.lower().endswith(('.xlsx', '.xls')):
            flash("Formato de arquivo inválido! Apenas arquivos Excel (.xlsx, .xls) são permitidos.", "danger")
            return redirect(request.url)

        try:
            # Ler o arquivo Excel
            df = pd.read_excel(file)

            # Limpar dados existentes antes de inserir novos
            ExcelData.query.delete()
            db.session.commit()

            # Processar e inserir novos dados
            for index, row in df.iterrows():
                # ---- Data: tenta converter de forma resiliente ----
                data = None
                # tenta colunas evidentes
                for col_name in df.columns:
                    col_norm = _norm_txt(col_name)
                    if col_norm in ['DATA', 'DT', 'DATE', 'DATAS']:
                        if pd.notna(row[col_name]):
                            if isinstance(row[col_name], pd.Timestamp):
                                data = row[col_name].date()
                            elif isinstance(row[col_name], datetime):
                                data = row[col_name].date()
                            elif isinstance(row[col_name], str):
                                date_formats = ['%Y-%m-%d', '%d/%m/%Y', '%d-%m-%Y', '%Y/%m/%d', '%m/%d/%Y']
                                for fmt in date_formats:
                                    try:
                                        data = datetime.strptime(row[col_name], fmt).date()
                                        break
                                    except ValueError:
                                        continue
                                if data is None:
                                    data = None
                            elif isinstance(row[col_name], (int, float)):
                                # tenta timestamp unix
                                try:
                                    data = datetime.fromtimestamp(row[col_name]).date()
                                except (ValueError, OSError, OverflowError):
                                    # tenta serial do excel
                                    try:
                                        excel_epoch = datetime(1899, 12, 30)  # base corrigida
                                        data = (excel_epoch + timedelta(days=row[col_name])).date()
                                    except (ValueError, OverflowError, TypeError):
                                        data = None
                        break  # já tratou a coluna "data" encontrada

                # ---- QTD HORAS ----
                qtd_horas = None
                for col_name in df.columns:
                    if _norm_txt(col_name) in ['QTD HORAS', 'QTD_HORAS', 'HORAS', 'QUANTIDADE_HORAS', 'QTDE_HORAS']:
                        if pd.notna(row[col_name]):
                            try:
                                qtd_horas = float(row[col_name])
                            except (ValueError, TypeError):
                                qtd_horas = None
                        break

                # ---- Campos de texto diversos (normalizados) ----
                matricula_raw = _get_value_by_possible_names(df, row, [
               'MATRICULA', 'MATRÍCULA', 'MATRICULA_FUNCIONARIO', 'ID_FUNCIONARIO'])

                if isinstance(matricula_raw, float):
                    matricula = str(int(matricula_raw))  # remove o .0
                elif isinstance(matricula_raw, (int, str)):
                    matricula = str(matricula_raw).split('.')[0]  # remove qualquer parte decimal
                else:
                    matricula = None
                nome = _to_upper_if_string(_get_value_by_possible_names(df, row, [
                        'NOME', 'NOME_FUNCIONARIO', 'FUNCIONARIO'
                    ]))
                cargo = _to_upper_if_string(_get_value_by_possible_names(df, row, [
                    'CARGO', 'CARGO_FUNCIONARIO', 'FUNCAO'
                ]))
                tipo_posicao2 = _to_upper_if_string(_get_value_by_possible_names(df, row, [
                    'TIPO POSIÇÃO 2', 'TIPO_POSICAO_2', 'TIPO', 'POSICAO_2', 'TIPO_VINCULO'
                ]))
                cargo_agrupado = _to_upper_if_string(_get_value_by_possible_names(df, row, [
                    'CARGO AGRUPADO', 'CARGO_AGRUPADO', 'CARGO_GRUPO', 'FUNCAO_GRUPO'
                ]))
                evento = _to_upper_if_string(_get_value_by_possible_names(df, row, [
                    'EVENTO', 'TIPO_EVENTO', 'OCORRENCIA'
                ]))
                gestor_imediato = _to_upper_if_string(_get_value_by_possible_names(df, row, [
                    'GESTOR IMEDIATO', 'GESTOR_IMEDIATO', 'SUPERVISOR', 'CHEFE_IMEDIATO'
                ]))
                gerente_imediato = _to_upper_if_string(_get_value_by_possible_names(df, row, [
                    'GERENTE IMEDIATO', 'GERENTE_IMEDIATO', 'GERENTE', 'COORDENADOR'
                ]))
                gerente_divisao = _to_upper_if_string(_get_value_by_possible_names(df, row, [
                    'GERENTE DIVISAO', 'GERENTE_DIVISAO', 'GERENTE_GERAL', 'DIRETOR_IMEDIATO'
                ]))
                cluster = _to_upper_if_string(_get_value_by_possible_names(df, row, [
                    'CLUSTER', 'REGIAO', 'AREA', 'UNIDADE'
                ]))
                diretoria = _to_upper_if_string(_get_value_by_possible_names(df, row, [
                    'DIRETORIA', 'DIRECAO', 'VICE_PRESIDENCIA'
                ]))

                excel_entry = ExcelData(
                    data=data,
                    matricula=matricula,
                    nome=nome,
                    cargo=cargo,
                    tipo_posicao2=tipo_posicao2,
                    cargo_agrupado=cargo_agrupado,
                    evento=evento,
                    qtd_horas=qtd_horas,
                    gestor_imediato=gestor_imediato,
                    gerente_imediato=gerente_imediato,
                    gerente_divisao=gerente_divisao,
                    cluster=cluster,
                    diretoria=diretoria,
                    filename=file.filename
                )
                db.session.add(excel_entry)

            db.session.commit()
            flash(f"Dados da planilha '{file.filename}' salvos com sucesso! {len(df)} registros inseridos.", "success")
            return redirect(url_for("excel_upload.upload_excel"))
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao processar o arquivo: {str(e)}", "danger")
            return redirect(request.url)

    return render_template("excel_upload.html")


@excel_upload_bp.route("/visualizacao-gerencial")
@login_required
@visao_gerencial_required
def visualizacao_gerencial():
    """
    Visão gerencial (diretoria): soma de HORAS A VENCER por EVENTO nas faixas:
      - NO MÊS / 1 MÊS  -> até 30
      - 2 MESES         -> 31-60
      - 3 MESES         -> 61-90
      - 4+ MESES        -> 120+
    """
    filtro_gerente = request.args.get('filtro_gerente', '').upper().strip()
    dados = ExcelData.query.all()

    # Totais globais
    horas_por_faixa = {
        'ate_30':    {'dias': 30,  'soma_horas': 0.0, 'classificacao': 'Crítico'},
        'de_31_60':  {'dias': 60,  'soma_horas': 0.0, 'classificacao': 'Atenção'},
        'de_61_90':  {'dias': 90,  'soma_horas': 0.0, 'classificacao': 'Regular'},
        'acima_120': {'dias': 120, 'soma_horas': 0.0, 'classificacao': 'Normal'},
    }

    dados_por_gerente = {}

    for r in dados:
        if r.qtd_horas is None or r.qtd_horas <= 0:
            continue
        if not r.evento:
            continue

        bucket = _bucket_por_evento(r.evento)
        if not bucket:
            continue

        gerente = (r.gerente_imediato or "").upper().strip()
        if not gerente:
            continue

        horas = float(r.qtd_horas)
        horas_por_faixa[bucket]['soma_horas'] += horas

        if gerente not in dados_por_gerente:
            dados_por_gerente[gerente] = {
                'soma_horas': 0.0,
                'horas_ate_30': 0.0,
                'horas_31_60': 0.0,
                'horas_61_90': 0.0,
                'horas_acima_120': 0.0,
                'colaboradores': [],
                'colaboradores_ate_30': [],
                'colaboradores_31_60': [],
                'colaboradores_61_90': [],
                'colaboradores_acima_120': [],
                'cargo': (r.cargo_agrupado or r.cargo or '')
            }

        g = dados_por_gerente[gerente]
        g['soma_horas'] += horas

        colab_info = {
            'nome': r.nome or 'NOME NÃO INFORMADO',
            'cargo': r.cargo or 'CARGO NÃO INFORMADO',
            'horas': horas,
        }

        if bucket == 'ate_30':
            g['horas_ate_30'] += horas
            g['colaboradores_ate_30'].append(colab_info)
        elif bucket == 'de_31_60':
            g['horas_31_60'] += horas
            g['colaboradores_31_60'].append(colab_info)
        elif bucket == 'de_61_90':
            g['horas_61_90'] += horas
            g['colaboradores_61_90'].append(colab_info)
        elif bucket == 'acima_120':
            g['horas_acima_120'] += horas
            g['colaboradores_acima_120'].append(colab_info)

        g['colaboradores'].append(colab_info)

    # Monta para o template
    gerentes_analise = []
    for gerente, info in dados_por_gerente.items():
        info['colaboradores_ate_30'].sort(key=lambda x: x['horas'], reverse=True)
        info['colaboradores_31_60'].sort(key=lambda x: x['horas'], reverse=True)
        info['colaboradores_61_90'].sort(key=lambda x: x['horas'], reverse=True)
        info['colaboradores_acima_120'].sort(key=lambda x: x['horas'], reverse=True)

        # Classificação visual por faixa mais "urgente" com horas > 0
        if info['horas_acima_120'] > 0:
            classificacao = 'Normal'; cor = 'success'
        elif info['horas_61_90'] > 0:
            classificacao = 'Regular'; cor = 'secondary'
        elif info['horas_31_60'] > 0:
            classificacao = 'Atenção'; cor = 'warning'
        elif info['horas_ate_30'] > 0:
            classificacao = 'Crítico'; cor = 'danger'
        else:
            classificacao = 'Normal'; cor = 'success'

        gerentes_analise.append({
            'nome': gerente,
            'cargo': info['cargo'],
            'soma_horas': info['soma_horas'],
            'horas_ate_30': info['horas_ate_30'],
            'horas_31_60': info['horas_31_60'],
            'horas_61_90': info['horas_61_90'],
            'horas_acima_120': info['horas_acima_120'],
            'colaboradores': sorted(info['colaboradores'], key=lambda x: x['horas'], reverse=True),
            'colaboradores_ate_30': info['colaboradores_ate_30'],
            'colaboradores_31_60': info['colaboradores_31_60'],
            'colaboradores_61_90': info['colaboradores_61_90'],
            'colaboradores_acima_120': info['colaboradores_acima_120'],
            'acima_30_dias': info['horas_ate_30'] > 0,
            'acima_60_dias': info['horas_31_60'] > 0,
            'acima_90_dias': info['horas_61_90'] > 0,
            'acima_120_dias': info['horas_acima_120'] > 0,
            'classificacao': classificacao,
            'classificacao_cor': cor
        })

    gerentes_filtrados = gerentes_analise
    if filtro_gerente:
        gerentes_filtrados = [g for g in gerentes_analise if filtro_gerente in g['nome']]

    # Ordena por soma de horas (peso total)
    gerentes_analise.sort(key=lambda x: x['soma_horas'], reverse=True)

    return render_template(
        "visualizacao_gerencial.html",
        gerentes=gerentes_analise,
        gerentes_filtrados=gerentes_filtrados,
        horas_por_faixa=horas_por_faixa,
        filtro_gerente=filtro_gerente
    )


@excel_upload_bp.route("/visualizacao-gerencial-gerente")
@login_required
@visao_gerencial_gerente_required
def visualizacao_gerencial_gerente():
    """
    Visão gerencial de gerente imediato:
    - Se role == 'gerente', mostra apenas o seu time (gerente_imediato == seu username).
    - Se admin/gestor, mostra todos (mantido para compatibilidade).
    """
    filtro_gerente = request.args.get('filtro_gerente', '').upper().strip()
    dados = ExcelData.query.all()

    if current_user.role == "gerente":
        meu_nome = (current_user.username or "").upper().strip()
        dados = [r for r in dados if (r.gerente_imediato or "").upper().strip() == meu_nome]

    # Totais (cards do topo da tela de gerente)
    horas_por_faixa = {
        'ate_30':    {'dias': 30,  'soma_horas': 0.0, 'classificacao': 'Crítico'},
        'de_31_60':  {'dias': 60,  'soma_horas': 0.0, 'classificacao': 'Atenção'},
        'de_61_90':  {'dias': 90,  'soma_horas': 0.0, 'classificacao': 'Regular'},
        'acima_120': {'dias': 120, 'soma_horas': 0.0, 'classificacao': 'Normal'},
    }

    dados_por_gerente = {}

    for r in dados:
        if r.qtd_horas is None or r.qtd_horas <= 0:
            continue
        if not r.evento:
            continue

        bucket = _bucket_por_evento(r.evento)
        if not bucket:
            continue

        gerente = (r.gerente_imediato or "").upper().strip()
        if not gerente:
            continue

        horas = float(r.qtd_horas)
        horas_por_faixa[bucket]['soma_horas'] += horas

        if gerente not in dados_por_gerente:
            dados_por_gerente[gerente] = {
                'soma_horas': 0.0,
                'horas_ate_30': 0.0,
                'horas_31_60': 0.0,
                'horas_61_90': 0.0,
                'horas_acima_120': 0.0,
                'colaboradores': [],
                'colaboradores_ate_30': [],
                'colaboradores_31_60': [],
                'colaboradores_61_90': [],
                'colaboradores_acima_120': [],
                'cargo': (r.cargo_agrupado or r.cargo or '')
            }

        g = dados_por_gerente[gerente]
        g['soma_horas'] += horas

        colab_info = {
            'nome': r.nome or 'NOME NÃO INFORMADO',
            'cargo': r.cargo or 'CARGO NÃO INFORMADO',
            'horas': horas,
        }

        if bucket == 'ate_30':
            g['horas_ate_30'] += horas
            g['colaboradores_ate_30'].append(colab_info)
        elif bucket == 'de_31_60':
            g['horas_31_60'] += horas
            g['colaboradores_31_60'].append(colab_info)
        elif bucket == 'de_61_90':
            g['horas_61_90'] += horas
            g['colaboradores_61_90'].append(colab_info)
        elif bucket == 'acima_120':
            g['horas_acima_120'] += horas
            g['colaboradores_acima_120'].append(colab_info)

        g['colaboradores'].append(colab_info)

    gerentes_analise = []
    for gerente, info in dados_por_gerente.items():
        info['colaboradores_ate_30'].sort(key=lambda x: x['horas'], reverse=True)
        info['colaboradores_31_60'].sort(key=lambda x: x['horas'], reverse=True)
        info['colaboradores_61_90'].sort(key=lambda x: x['horas'], reverse=True)
        info['colaboradores_acima_120'].sort(key=lambda x: x['horas'], reverse=True)

        if info['horas_acima_120'] > 0:
            classificacao = 'Normal'; cor = 'success'
        elif info['horas_61_90'] > 0:
            classificacao = 'Regular'; cor = 'secondary'
        elif info['horas_31_60'] > 0:
            classificacao = 'Atenção'; cor = 'warning'
        elif info['horas_ate_30'] > 0:
            classificacao = 'Crítico'; cor = 'danger'
        else:
            classificacao = 'Normal'; cor = 'success'

        gerentes_analise.append({
            'nome': gerente,
            'cargo': info['cargo'],
            'soma_horas': info['soma_horas'],
            'horas_ate_30': info['horas_ate_30'],
            'horas_31_60': info['horas_31_60'],
            'horas_61_90': info['horas_61_90'],
            'horas_acima_120': info['horas_acima_120'],
            'colaboradores': sorted(info['colaboradores'], key=lambda x: x['horas'], reverse=True),
            'colaboradores_ate_30': info['colaboradores_ate_30'],
            'colaboradores_31_60': info['colaboradores_31_60'],
            'colaboradores_61_90': info['colaboradores_61_90'],
            'colaboradores_acima_120': info['colaboradores_acima_120'],
            'acima_30_dias': info['horas_ate_30'] > 0,
            'acima_60_dias': info['horas_31_60'] > 0,
            'acima_90_dias': info['horas_61_90'] > 0,
            'acima_120_dias': info['horas_acima_120'] > 0,
            'classificacao': classificacao,
            'classificacao_cor': cor
        })

    gerentes_filtrados = gerentes_analise
    if filtro_gerente:
        gerentes_filtrados = [g for g in gerentes_analise if filtro_gerente in g['nome']]

    gerentes_analise.sort(key=lambda x: x['soma_horas'], reverse=True)

    return render_template(
        "visualizacao_gerencial.html",
        gerentes=gerentes_analise,
        gerentes_filtrados=gerentes_filtrados,
        horas_por_faixa=horas_por_faixa,
        filtro_gerente=filtro_gerente
    )


@excel_upload_bp.route("/visualizacao-ferias")
@login_required
@visao_gerencial_required
def visualizacao_ferias():
    """
    Visão de controle de férias para diretoria.
    Agrupa solicitações de férias (Pendente/Aprovado) e cruza com a base Excel para exibir contexto.
    """
    # Base Excel e férias
    dados = ExcelData.query.all()
    ferias_pendentes = Request.query.filter_by(type="Ferias").filter(
        Request.status.in_(["Pendente", "Aprovado"])
    ).all()

    # Agrupa férias por funcionário (nome)
    ferias_por_funcionario = {}
    for fer in ferias_pendentes:
        funcionario_nome = fer.user.username if fer.user else "DESCONHECIDO"
        if funcionario_nome not in ferias_por_funcionario:
            ferias_por_funcionario[funcionario_nome] = {'periodos': [], 'dias_totais': 0, 'status': fer.status}
        dias_periodo = (fer.end_date - fer.start_date).days + 1
        ferias_por_funcionario[funcionario_nome]['periodos'].append({
            'inicio': fer.start_date,
            'fim': fer.end_date,
            'dias': dias_periodo,
            'status': fer.status
        })
        ferias_por_funcionario[funcionario_nome]['dias_totais'] += dias_periodo
        ferias_por_funcionario[funcionario_nome]['status'] = fer.status

    # Separa marcadas x não marcadas
    ferias_marcadas = []
    ferias_nao_marcadas = []
    for registro in dados:
        if not registro.nome:
            continue
        nome_func = registro.nome
        tem_ferias = nome_func in ferias_por_funcionario

        info = {
            'nome': nome_func,
            'cargo': registro.cargo,
            'gestor_imediato': registro.gestor_imediato,
            'data_registro': registro.data
        }
        if tem_ferias:
            info.update(ferias_por_funcionario[nome_func])
            ferias_marcadas.append(info)
        else:
            # Dias desde o primeiro registro na base
            if registro.data:
                dias_desde_registro = (date.today() - registro.data).days
                info['dias_desde_registro'] = dias_desde_registro
            ferias_nao_marcadas.append(info)

    ferias_marcadas.sort(key=lambda x: x['nome'])
    ferias_nao_marcadas.sort(key=lambda x: x.get('dias_desde_registro', 0), reverse=True)

    return render_template(
        "visualizacao_ferias.html",
        ferias_marcadas=ferias_marcadas,
        ferias_nao_marcadas=ferias_nao_marcadas
    )


@excel_upload_bp.route("/visualizacao-ferias-gerente")
@login_required
@visao_gerencial_gerente_required
def visualizacao_ferias_gerente():
    """
    Visão de controle de férias para GERENTES: mostra apenas sua equipe.
    """
    # Subordinados do gerente logado
    subordinados = User.query.filter_by(gestor_id=current_user.id).all()
    nomes_subordinados = [sub.username.upper() for sub in subordinados]

    # Base Excel apenas da equipe
    dados_equipe = ExcelData.query.filter(
        ExcelData.nome.in_(nomes_subordinados)
    ).all() if nomes_subordinados else []

    # Férias apenas dos subordinados
    subordinados_ids = [sub.id for sub in subordinados]
    ferias_pendentes = Request.query.filter(
        Request.user_id.in_(subordinados_ids),
        Request.type == "Ferias",
        Request.status.in_(["Pendente", "Aprovado"])
    ).all()

    # Agrupa por funcionário
    ferias_por_funcionario = {}
    for fer in ferias_pendentes:
        funcionario_nome = fer.user.username if fer.user else "DESCONHECIDO"
        if funcionario_nome not in ferias_por_funcionario:
            ferias_por_funcionario[funcionario_nome] = {'periodos': [], 'dias_totais': 0, 'status': fer.status}
        dias_periodo = (fer.end_date - fer.start_date).days + 1
        ferias_por_funcionario[funcionario_nome]['periodos'].append({
            'inicio': fer.start_date,
            'fim': fer.end_date,
            'dias': dias_periodo,
            'status': fer.status
        })
        ferias_por_funcionario[funcionario_nome]['dias_totais'] += dias_periodo
        ferias_por_funcionario[funcionario_nome]['status'] = fer.status

    ferias_marcadas = []
    ferias_nao_marcadas = []
    for registro in dados_equipe:
        if not registro.nome:
            continue
        nome_funcionario = registro.nome
        tem_ferias = nome_funcionario in ferias_por_funcionario

        info = {
            'nome': nome_funcionario,
            'cargo': registro.cargo,
            'gestor_imediato': registro.gestor_imediato,
            'gerente_imediato': registro.gerente_imediato,
            'data_registro': registro.data
        }
        if tem_ferias:
            info.update(ferias_por_funcionario[nome_funcionario])
            ferias_marcadas.append(info)
        else:
            if registro.data:
                dias_desde_registro = (date.today() - registro.data).days
                info['dias_desde_registro'] = dias_desde_registro
            ferias_nao_marcadas.append(info)

    ferias_marcadas.sort(key=lambda x: x['nome'])
    ferias_nao_marcadas.sort(key=lambda x: x.get('dias_desde_registro', 0), reverse=True)

    return render_template(
        "visualizacao_ferias_gerente.html",
        ferias_marcadas=ferias_marcadas,
        ferias_nao_marcadas=ferias_nao_marcadas
    )


@excel_upload_bp.route("/download-excel-template")
@login_required
@excel_upload_required
def download_template():
    """Baixa um template Excel vazio com colunas esperadas."""
    template_data = {
        'DATA': [],
        'MATRICULA': [],
        'NOME': [],
        'CARGO': [],
        'TIPO POSIÇÃO 2': [],
        'CARGO AGRUPADO': [],
        'EVENTO': [],
        'QTD HORAS': [],
        'GESTOR IMEDIATO': [],
        'GERENTE IMEDIATO': [],
        'GERENTE_DIVISAO': [],
        'CLUSTER': [],
        'DIRETORIA': []
    }
    df = pd.DataFrame(template_data)

    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Template')
    buffer.seek(0)

    return Response(
        buffer.getvalue(),
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': 'attachment; filename="template_excel_upload.xlsx"'}
    )