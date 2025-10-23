#!/usr/bin/env python3
"""
Script para atualizar o tipo de autenticação dos usuários existentes
"""
import sys
import os
from datetime import date

# Adicionar o diretório ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import User


def update_auth_type():
    """
    Atualiza o campo auth_type para usuários existentes:
    - Usuários com password="ad_auth_placeholder" -> auth_type="ad"
    - Outros usuários -> auth_type="local"
    """
    app = create_app()
    
    with app.app_context():
        # Atualizar usuários com senha placeholder (AD) para auth_type="ad"
        usuarios_com_ad = User.query.filter_by(password="ad_auth_placeholder").all()
        
        for usuario in usuarios_com_ad:
            if usuario.auth_type != "ad":
                usuario.auth_type = "ad"
                print(f"✓ Atualizado usuário AD: {usuario.email}")
        
        # Atualizar demais usuários para auth_type="local"
        usuarios_locais = User.query.filter(
            User.password != "ad_auth_placeholder"
        ).all()
        
        for usuario in usuarios_locais:
            if usuario.auth_type != "local":
                usuario.auth_type = "local"
                print(f"✓ Atualizado usuário local: {usuario.email}")
        
        try:
            db.session.commit()
            print(f"\\n✅ Atualização concluída: {len(usuarios_com_ad)} usuários AD e {len(usuarios_locais)} usuários locais atualizados")
        except Exception as e:
            db.session.rollback()
            print(f"❌ Erro ao atualizar: {e}")


if __name__ == "__main__":
    update_auth_type()