import sys
import os
from datetime import date

# Adicionar o diretório ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import User
from werkzeug.security import generate_password_hash
def create_users():
    app = create_app()
    
    with app.app_context():
        # Criar tabelas se não existirem
        db.create_all()
        
        # Verificar se já existem usuários
        users_count = User.query.count()
        print(f"Total de usuários no banco: {users_count}")
        
        # Adicionar usuário admin
        admin = User.query.filter_by(email='admin@empresa.com').first()
        if not admin:
            admin = User(
                email='admin@empresa.com',
                username='Administrador do Sistema',
                password=generate_password_hash('Root@10!'),
                auth_type='local',
                role='admin',
                sexo='M'
            )
            db.session.add(admin)
            print("✓ Administrador criado: admin@empresa.com / admin123")
        else:
            print("⚠ Administrador já existe")
        
        # # Lista de usuários comuns para criar
        # usuarios_comuns = [
        #     {
        #         "email": "usuario@empresa.com",
        #         "username": "Usuário Comum",
        #         "sexo": "M",
        #         "aniversario": date(2000, 12, 15)
        #     },
        #     {
        #         "email": "caio@empresa.com",
        #         "username": "Caio Silva",
        #         "sexo": "M",
        #         "aniversario": date(2000, 12, 15)
        #     },
        #     {
        #         "email": "ana@empresa.com",
        #         "username": "Ana Souza",
        #         "sexo": "F",
        #         "aniversario": date(1987, 1, 5)
        #     }
        # ]
        
        # usuarios_criados = []
        # for u in usuarios_comuns:
        #     usuario = User.query.filter_by(email=u["email"]).first()
        #     if not usuario:
        #         usuario = User(
        #             email=u["email"],
        #             username=u["username"],
        #             password=generate_password_hash('usuario123'),
        #             auth_type='local',
        #             role='user',
        #             sexo=u["sexo"],
        #             aniversario=u["aniversario"]
        #         )
        #         db.session.add(usuario)
        #         usuarios_criados.append(u["email"])
        #         print(f"✓ Usuário comum criado: {u['email']} / usuario123")
        #     else:
        #         print(f"⚠ Usuário comum já existe: {u['email']}")
        
        # # Criar gestor
        # gestor = User.query.filter_by(email='gestor@empresa.com').first()
        # if not gestor:
        #     gestor = User(
        #         email='gestor@empresa.com',
        #         username='Gestor da Equipe',
        #         password=generate_password_hash('gestor123'),
        #         auth_type='local',
        #         role='gestor',
        #         sexo='M',
        #         aniversario=date(1985, 7, 20)
        #     )
        #     db.session.add(gestor)
        #     print("✓ Gestor criado: gestor@empresa.com / gestor123")
        # else:
        #     print("⚠ Gestor já existe")
        
        # # Associar usuário comum ao gestor (exemplo: usuario@empresa.com)
        # usuario_comum = User.query.filter_by(email='usuario@empresa.com').first()
        # if usuario_comum and gestor and getattr(usuario_comum, 'gestor_id', None) is None:
        #     usuario_comum.gestor_id = gestor.id
        #     print("✓ Usuário associado ao gestor")
        
        try:
            db.session.commit()
            print("\n✅ Usuários criados com sucesso!")
            print("\nCredenciais criadas:")
            # for u in usuarios_comuns:
            #     print(f"👤 Usuário comum: {u['email']} / usuario123")
            # print("👨‍💼 Gestor: gestor@empresa.com / gestor123")
            print("👑 Administrador: admin@empresa.com / admin123")
        except Exception as e:
            db.session.rollback()
            print(f"❌ Erro ao criar usuários: {e}")

if __name__ == "__main__":
    create_users()
