from . import db, login_manager
from flask_login import UserMixin
from datetime import date, datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import calendar

# Opcional (você já tinha importado LONGTEXT; manterei db.Text para portabilidade)
from sqlalchemy.dialects.mysql import LONGTEXT
import json


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=True)  # Tornando nullable=True para permitir setter customizado
    password = db.Column(db.String(200), nullable=False)

    # Tipo de autenticação: 'ad' para Active Directory, 'local' para usuário local
    auth_type = db.Column(db.String(10), default="local", nullable=False)

    # Papéis suportados: "admin", "gerente", "gestor", "focal", "user", "diretor", "gerente senior"
    role = db.Column(db.String(20), default="user")

    # ---- NOVOS CAMPOS ----
    # Origem do papel e trava de admin
    # 'AD' | 'ADMIN' | 'LOCAL'
    role_source = db.Column(db.String(10), default="AD")
    role_locked_by_admin = db.Column(db.Boolean, default=False)
    updated_by_admin_at = db.Column(db.DateTime, nullable=True)

    # Últimos dados vistos do AD (auditoria)
    ad_title_last_seen = db.Column(db.String(150), nullable=True)
    ad_groups_last_seen = db.Column(db.Text, nullable=True)

    aniversario = db.Column(db.Date, nullable=True)
    sexo = db.Column(db.String(10), nullable=True)

    # Se for usuário, aponta para o gestor responsável
    # Adicionamos index=True para acelerar consultas por equipe
    gestor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    subordinados = db.relationship(
        "User",
        backref=db.backref("gestor", remote_side=[id]),
        lazy=True
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Converter campos para maiúsculas durante a inicialização
        if hasattr(self, '_username') and self._username:
            self._username = self._username.upper()

    def __setattr__(self, name, value):
        # Converter para maiúsculas os campos textuais apropriados, exceto o role
        if name in ['username', 'email', 'sexo'] and isinstance(value, str) and name != 'role':
            value = value.upper()
        super().__setattr__(name, value)

    def __repr__(self):
        return f'<User {self.email}>'

    # Helpers opcionais (úteis para templates/sessão)
    @property
    def gestor_nome(self):
        return self.gestor.username if self.gestor else None

    @property
    def gestor_email(self):
        return self.gestor.email if self.gestor else None

    @property
    def is_gestor(self) -> bool:
        """
        Indica se o usuário atua como gestor ou gerente:
        - Se o role for 'gerente', 'gestor' ou 'admin', ou
        - Se ele possuir subordinados vinculados.
        """
        try:
            # Quando lazy=True, subordinados já é uma lista em memória
            return (self.role in ("gerente", "gestor", "admin")) or (self.subordinados and len(self.subordinados) > 0)
        except Exception:
            return self.role in ("gerente", "gestor", "admin")

    # --- Senha (somente para logins locais) ---
    def set_password(self, raw_password: str):
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        # Em contas AD, a senha é "ad_auth_placeholder" e check vai falhar (como esperado)
        try:
            return check_password_hash(self.password, raw_password)
        except Exception:
            return False


# 🚨 Essencial para o Flask-Login funcionar
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class ExcelData(db.Model):
    __tablename__ = "FREQUENCIA"

    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Date, nullable=True)
    matricula = db.Column(db.String(50), nullable=True)
    nome = db.Column(db.String(200), nullable=True)
    cargo = db.Column(db.String(200), nullable=True)
    tipo_posicao2 = db.Column(db.String(100), nullable=True)  # TIPO POSIÇÃO 2
    cargo_agrupado = db.Column(db.String(200), nullable=True)
    evento = db.Column(db.String(100), nullable=True)
    qtd_horas = db.Column(db.Float, nullable=True)
    gestor_imediato = db.Column(db.String(200), nullable=True)
    gerente_imediato = db.Column(db.String(200), nullable=True)
    gerente_divisao = db.Column(db.String(200), nullable=True)
    cluster = db.Column(db.String(100), nullable=True)
    diretoria = db.Column(db.String(100), nullable=True)

    # Armazenar o nome do arquivo para referência
    filename = db.Column(db.String(200), nullable=True)

    # Data de upload
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)


class Request(db.Model):
    __tablename__ = "request"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    type = db.Column(
        db.String(50), nullable=False
    )  # "BH", "Ferias", "Dayoff", "Maternidade", "Paternidade"
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default="Pendente")  # Pendente, Aprovado, Rejeitado

    user = db.relationship("User", backref=db.backref("requests", lazy=True))

    def get_feriados_brasil(self, ano):
        """Retorna lista de feriados fixos do Brasil"""
        feriados = [
            date(ano, 1, 1),   # Ano Novo
            date(ano, 4, 21),  # Tiradentes
            date(ano, 5, 1),   # Dia do Trabalho
            date(ano, 9, 7),   # Independência
            date(ano, 10, 12), # Nossa Senhora Aparecida
            date(ano, 11, 2),  # Finados
            date(ano, 11, 15), # Proclamação da República
            date(ano, 12, 25), # Natal
        ]
        return feriados

    def is_feriado(self, data):
        """Verifica se uma data é feriado"""
        feriados = self.get_feriados_brasil(data.year)
        return data in feriados

    def is_final_semana(self, data):
        """Verifica se uma data é sábado ou domingo"""
        return data.weekday() >= 5  # 5 = sábado, 6 = domingo

    def validate(self):
        """Validações específicas de cada tipo de solicitação"""
        errors = []
        delta_days = (self.end_date - self.start_date).days + 1

        # Verificar se a data de início é posterior à data de fim
        if self.start_date > self.end_date:
            errors.append("A data de início não pode ser posterior à data de fim.")

        if self.type == "Ferias":
            if self.start_date < date.today():
                errors.append("A data de início das férias não pode ser anterior à data atual.")
            if delta_days > 30:
                errors.append("Férias não podem ultrapassar 30 dias.")
            weekday = self.start_date.weekday()
            if weekday > 2:  # 0=seg, 1=ter, 2=qua
                errors.append("Férias devem iniciar na segunda, terça ou quarta-feira.")

        if self.type == "Dayoff":
            if delta_days > 1:
                errors.append("Dayoff deve ser apenas 1 dia.")
            existing = Request.query.filter(
                Request.user_id == self.user_id,
                Request.type == "Dayoff",
                Request.start_date >= date(self.start_date.year, 1, 1),
                Request.start_date <= date(self.start_date.year, 12, 31)
            ).all()
            for r in existing:
                if r.id != self.id:
                    errors.append("Você já utilizou seu Dayoff este ano.")

            user_obj = self.user or User.query.get(self.user_id)
            if not user_obj or not user_obj.aniversario:
                errors.append("Data de aniversário não cadastrada. Contate o administrador.")
            else:
                aniversario_ano_atual = user_obj.aniversario.replace(year=self.start_date.year)
                diff = abs((self.start_date - aniversario_ano_atual).days)
                if diff > 15:
                    errors.append("Dayoff só pode ser solicitado até 15 dias antes ou depois do seu aniversário (incluindo o próprio dia).")

                data_limite_retroativa = aniversario_ano_atual + timedelta(days=15)
                if date.today() > data_limite_retroativa:
                    errors.append("Não é possível solicitar Dayoff retroativamente após 15 dias do seu aniversário.")

                if self.is_final_semana(self.start_date) or self.is_feriado(self.start_date):
                    errors.append("Dayoff não pode ser solicitado em finais de semana ou feriados.")

        if self.type == "Maternidade":
            user_obj = self.user or User.query.get(self.user_id)
            if not user_obj or not user_obj.sexo:
                errors.append("Sexo não cadastrado. Contate o administrador.")
            elif user_obj.sexo != "F":
                errors.append("Licença maternidade só pode ser solicitada por usuárias do sexo feminino.")
            if delta_days != 180:
                errors.append("Licença maternidade deve ser exatamente 6 meses (180 dias).")

        if self.type == "Paternidade":
            user_obj = self.user or User.query.get(self.user_id)
            if not user_obj or not user_obj.sexo:
                errors.append("Sexo não cadastrado. Contate o administrador.")
            elif user_obj.sexo != "M":
                errors.append("Licença paternidade só pode ser solicitada por usuários do sexo masculino.")
            if delta_days != 30:
                errors.append("Licença paternidade deve ser exatamente 1 mês (30 dias).")

        if self.type == "BH":
            current_date = self.start_date
            while current_date <= self.end_date:
                if self.is_final_semana(current_date) or self.is_feriado(current_date):
                    errors.append(f"Banco de Horas não pode incluir a data {current_date.strftime('%d/%m/%Y')} (fim de semana ou feriado).")
                current_date += timedelta(days=1)

        return errors
