from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave-secreta'  # Troque por uma chave segura

# Configuração do banco de dados PostgreSQL do Render
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://kiko:BvcMtbWTHpdnhtVr3Oz3G474l9e1WzEE@dpg-culb7i2n91rc73e9mbm0-a.oregon-postgres.render.com/dbkiko'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelo de Usuário com Hash de Senha
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # Alterado para armazenar o hash da senha

    # Método para definir a senha (gera hash)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Método para verificar a senha (compara o hash)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # Verifica se o usuário existe e se a senha está correta
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Login inválido. Tente novamente!')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Bem-vindo, {current_user.username}! <a href="/logout">Logout</a>'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Rota para cadastrar usuários manualmente (temporário para testes)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verifica se o usuário já existe
        if User.query.filter_by(username=username).first():
            flash('Usuário já existe. Escolha outro nome!')
            return redirect(url_for('register'))

        # Cria um novo usuário com senha criptografada
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Usuário cadastrado com sucesso! Faça login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')
if __name__ == '__main__':
    with app.app_context():
        db.drop_all()  # Apaga todas as tabelas
        db.create_all()  # Recria todas as tabelas corretamente
        print("Banco de dados atualizado!")
    app.run(debug=True)


