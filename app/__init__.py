# app/__init__.py
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    load_dotenv()  # carrega SECRET_KEY, DATABASE_URL, FLASK_ENV, etc.

    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev")
    database_url = os.getenv("DATABASE_URL", "")
    if database_url and ("mysql" in database_url or "mariadb" in database_url):
        # Para MySQL/MariaDB, garantir que o nome do banco de dados esteja presente
        if database_url.count('/') < 3:
            # Se o nome do banco de dados não estiver incluído, adicionar
            parts = database_url.split('/', 3)
            if len(parts) == 3:
                database_url = f"{parts[0]}//{parts[2]}/planejamento"
        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    elif database_url.startswith("sqlite"):
        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    else:
        # Fallback para SQLite
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///planejamento.db"
    
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Inicializa extensões
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    # login_manager.login_message_category = "info"  # opcional

    # Registrar blueprints
    from .auth import auth_bp
    from .solicitacao import solicitacao_bp
    from .requests import requests_bp
    from .gestor import gestor_bp
    from .admin import admin_bp
    from .excel_upload import excel_upload_bp

    app.register_blueprint(admin_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(solicitacao_bp)
    app.register_blueprint(requests_bp)
    app.register_blueprint(gestor_bp)
    app.register_blueprint(excel_upload_bp)

    # Adicionar filtro personalizado para converter JSON
    import json
    @app.template_filter('from_json')
    def from_json_filter(value):
        try:
            return json.loads(value) if value else {}
        except (TypeError, ValueError):
            return {}

    # Criação de tabelas só em desenvolvimento
    if os.getenv("FLASK_ENV") == "development":
        with app.app_context():
            db.create_all()

    return app
