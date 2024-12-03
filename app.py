from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necessário para usar flash()

# Configuração do banco de dados (SQLite para testes; pode alterar para MySQL depois)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///agendamentos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo do banco de dados para agendamentos
class Agendamento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    telefone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    data = db.Column(db.Date, nullable=False)
    horario = db.Column(db.String(5), nullable=False)
    mensagem = db.Column(db.Text, nullable=True)

# Modelo de usuário para o login
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    senha = db.Column(db.String(200), nullable=False)

# Rota para exibir o formulário
@app.route('/')
def index():
    return render_template('formulario.html')

# Rota para processar o agendamento
@app.route('/agendar', methods=['POST'])
def agendar():
    nome = request.form['nome']
    telefone = request.form['telefone']
    email = request.form['email']
    data = datetime.strptime(request.form['data'], '%Y-%m-%d').date()
    horario = request.form['horario']
    mensagem = request.form.get('mensagem')

    # Criação de um novo agendamento
    novo_agendamento = Agendamento(
        nome=nome, telefone=telefone, email=email, data=data, horario=horario, mensagem=mensagem
    )

    # Salvar no banco de dados
    db.session.add(novo_agendamento)
    db.session.commit()

    # Mensagem flash para informar o sucesso
    flash('Agendamento realizado com sucesso!.', 'success')

    return redirect(url_for('index'))

@app.route('/adicionar_usuario', methods=['GET', 'POST'])
def adicionar_usuario():
    if 'usuario_id' not in session:
        flash('Você precisa estar logado para adicionar um usuário.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        senha = request.form['senha']

        # Verificar se o username já existe
        if Usuario.query.filter_by(username=username).first():
            flash('O nome de usuário já está em uso. Escolha outro.', 'danger')
            return render_template('adicionar_usuario.html')

        # Criação do hash da senha
        senha_hash = generate_password_hash(senha)

        # Criar o novo usuário
        novo_usuario = Usuario(username=username, senha=senha_hash)

        try:
            # Adicionar ao banco de dados
            db.session.add(novo_usuario)
            db.session.commit()

            flash('Usuário criado com sucesso!', 'success')
            return redirect(url_for('lista_usuarios'))  # Redireciona para a lista de usuários
        except IntegrityError:
            db.session.rollback()  # Desfaz a transação se ocorrer um erro
            flash('Erro ao criar o usuário. Tente novamente.', 'danger')

    return render_template('adicionar_usuario.html')  # Exibe o formulário para adicionar usuário

@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
def editar_usuario(id):
    usuario = Usuario.query.get_or_404(id)  # Busca o usuário pelo ID
    if request.method == 'POST':
        # Atualiza os campos do usuário
        usuario.username = request.form['username']
        usuario.senha = generate_password_hash(request.form['senha'])  # Atualiza a senha com hash

        # Salva no banco de dados
        db.session.commit()

        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('lista_usuarios'))  # Redireciona para a lista de usuários

    return render_template('editar_usuario.html', usuario=usuario)  # Exibe o formulário de edição

@app.route('/usuarios')
def lista_usuarios():
    if 'usuario_id' not in session:
        flash('Você precisa estar logado para acessar esta página.', 'warning')
        return redirect(url_for('login'))
    
    # Recupera o nome do usuário logado
    nome_usuario = session.get('username')  # Obtém o nome do usuário da sessão

    usuarios = Usuario.query.all()  # Recupera todos os usuários do banco de dados
    return render_template('lista_usuarios.html', usuarios=usuarios, nome_usuario=nome_usuario)

@app.route('/usuario/<int:id>')
def perfil_usuario(id):
    if 'usuario_id' not in session:
        flash('Você precisa estar logado para acessar esta página.', 'warning')
        return redirect(url_for('login'))

    usuario = Usuario.query.get_or_404(id)  # Recupera o usuário pelo ID
    return render_template('perfil_usuario.html', usuario=usuario)

@app.route('/deletar_usuario/<int:id>', methods=['GET'])
def deletar_usuario(id):
    if 'usuario_id' not in session:
        flash('Você precisa estar logado para realizar esta ação.', 'warning')
        return redirect(url_for('login'))

    usuario = Usuario.query.get_or_404(id)  # Recupera o usuário pelo ID
    db.session.delete(usuario)  # Exclui o usuário
    db.session.commit()  # Salva a mudança no banco de dados
    flash('Usuário excluído com sucesso!', 'success')
    return redirect(url_for('lista_usuarios'))  # Redireciona para a lista de usuários

# Rota para exibir a página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        senha = request.form['senha']
        usuario = Usuario.query.filter_by(username=username).first()
        
        if usuario and check_password_hash(usuario.senha, senha):
            session['usuario_id'] = usuario.id
            session['username'] = usuario.username
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('lista_agendamentos'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
    
    return render_template('login.html')

# Rota para exibir a lista de agendamentos (somente para usuários autenticados)
@app.route('/agendamentos')
def lista_agendamentos():
    if 'usuario_id' not in session:
        flash('Você precisa estar logado para acessar esta página.', 'warning')
        return redirect(url_for('login'))
    
    # Recupera o nome do usuário logado
    nome_usuario = session.get('username')  # Obtém o nome do usuário da sessão

    # Verifica se o usuário deseja filtrar os agendamentos para o dia atual
    filtrar_dia_atual = request.args.get('filtro', 'todos') == 'hoje'
    hoje = datetime.now().date()

    if filtrar_dia_atual:
        agendamentos = Agendamento.query.filter_by(data=hoje).all()
    else:
        agendamentos = Agendamento.query.all()

    return render_template(
        'lista_agendamentos.html',
        agendamentos=agendamentos,
        nome_usuario=nome_usuario,
        filtro=filtrar_dia_atual
    )

    agendamentos = Agendamento.query.all()  # Recupera todos os agendamentos do banco de dados
    return render_template('lista_agendamentos.html', agendamentos=agendamentos, nome_usuario=nome_usuario)

# Rota para deletar um agendamento
@app.route('/deletar/<int:id>')
def deletar(id):
    if 'usuario_id' not in session:
        flash('Você precisa estar logado para realizar esta ação.', 'warning')
        return redirect(url_for('login'))

    agendamento = Agendamento.query.get_or_404(id)  # Recupera o agendamento pelo ID
    db.session.delete(agendamento)  # Exclui o agendamento
    db.session.commit()  # Salva a mudança no banco de dados
    return redirect(url_for('lista_agendamentos'))  # Redireciona para a página de agendamentos

@app.route('/horarios_indisponiveis', methods=['GET'])
def horarios_indisponiveis():
    data = request.args.get('data')  # Pega a data enviada na requisição
    if not data:
        return {"error": "Data não fornecida."}, 400

    try:
        data_obj = datetime.strptime(data, '%Y-%m-%d').date()
    except ValueError:
        return {"error": "Formato de data inválido."}, 400

    # Consulta os horários ocupados para a data específica
    agendamentos = Agendamento.query.filter_by(data=data_obj).all()
    horarios = [agendamento.horario for agendamento in agendamentos]

    return {"horarios_indisponiveis": horarios}

# Rota para logout
@app.route('/logout', methods=['GET'])
def logout():
    session.pop('usuario_id', None)  # Remove a sessão do usuário
    session.pop('username', None)
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('login'))  # Redireciona para a página de login

if __name__ == "__main__":
    app.run(debug=True)
