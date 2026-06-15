const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const { Pool } = require('pg'); 
const jwt = require('jsonwebtoken'); 

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

// Configuração do seu Banco de Dados (Confira bem a senha!)
const banco = new Pool({
    user: 'postgres',          
    host: 'localhost',         
    database: 'portart_db',    
    password: '127869', // <-- Lembra de colocar sua senha aqui!
    port: 5432,
    connectionTimeoutMillis: 5000 // Se o banco não responder em 5 segundos, desiste em vez de travar
});

// Testar a conexão de forma direta
banco.connect((erro) => {
    if (erro) {
        console.log('===================================================');
        console.error('❌ ERRO CRÍTICO NO BANCO:', erro.message);
        console.log('===================================================');
    } else {
        console.log('===================================================');
        console.log('✅ Conexão com o PostgreSQL firme e forte!');
        console.log('===================================================');
    }
});

const CHAVE_SECRETA_JWT = "ChaveSecretaDoProjetoPortArt2026";

// Rota Principal
app.get('/', (req, res) => {
    res.send('Backend do PortArt rodando!');
});

// =========================================================================
// ROTAS EXISTENTES (Cadastro, Login e Criar Post mantidos)
// =========================================================================
app.post('/api/usuarios', async (req, res) => {
    const { nome, email, senha } = req.body;
    if (!nome || !email || !senha) return res.status(400).json({ erro: "Preencha tudo!" });
    try {
        const checarEmail = await banco.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (checarEmail.rows.length > 0) return res.status(400).json({ erro: "E-mail já cadastrado!" });
        const senhaCriptografada = await bcrypt.hash(senha, 10);
        const novoUsuario = await banco.query('INSERT INTO usuarios (nome, email, senha) VALUES ($1, $2, $3) RETURNING id, nome, email', [nome, email, senhaCriptografada]);
        res.status(201).json({ mensagem: "Sucesso!", usuario: novoUsuario.rows[0] });
    } catch (erro) { res.status(500).json({ erro: erro.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ erro: "Informe e-mail e senha!" });
    try {
        const busca = await banco.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (busca.rows.length === 0) return res.status(401).json({ erro: "Incorretos!" });
        const usuario = busca.rows[0];
        const senhaEstaCorreta = await bcrypt.compare(senha, usuario.senha);
        if (!senhaEstaCorreta) return res.status(401).json({ erro: "Incorretos!" });
        const token = jwt.sign({ id: usuario.id, nome: usuario.nome }, CHAVE_SECRETA_JWT, { expiresIn: '1d' });
        res.json({ mensagem: "Login feito!", token: token, usuario: { id: usuario.id, nome: usuario.nome } });
    } catch (erro) { res.status(500).json({ erro: erro.message }); }
});

app.get('/api/simular-login', async (req, res) => {
    try {
        const resposta = await fetch('http://localhost:3000/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: "edu@teste.com", senha: "senhaSuperSegura123" })
        });
        const dados = await resposta.json();
        res.json(dados);
    } catch (erro) { res.status(500).json({ erro: erro.message }); }
});

// MIDDLEWARE DE SEGURANÇA
function conferirAutenticacao(req, res, next) {
    const cabecalhoAutenticacao = req.headers['authorization'];
    const token = cabecalhoAutenticacao && cabecalhoAutenticacao.split(' ')[1];

    if (!token) return res.status(401).json({ erro: "Acesso negado!" });

    try {
        const dadosDoToken = jwt.verify(token, CHAVE_SECRETA_JWT);
        req.usuarioLogado = dadosDoToken;
        next();
    } catch (erro) {
        return res.status(403).json({ erro: "Token inválido!" });
    }
}

app.post('/api/conteudos/criar', conferirAutenticacao, async (req, res) => {
    const { titulo, descricao, midia_url } = req.body;
    const usuarioId = req.usuarioLogado.id; 
    if (!titulo) return res.status(400).json({ erro: "O título é obrigatório!" });
    try {
        const novoPost = await banco.query('INSERT INTO conteudos (usuario_id, titulo, descricao, midia_url) VALUES ($1, $2, $3, $4) RETURNING *', [usuarioId, titulo, descricao, midia_url]);
        res.status(201).json({ mensagem: "Publicação criada com sucesso na conta de " + req.usuarioLogado.nome, post: novoPost.rows[0] });
    } catch (erro) { res.status(500).json({ erro: erro.message }); }
});

app.get('/api/simular-post', async (req, res) => {
    try {
        const respostaLogin = await fetch('http://localhost:3000/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: "edu@teste.com", senha: "senhaSuperSegura123" })
        });
        const dadosLogin = await respostaLogin.json();
        const meuToken = dadosLogin.token;
        const respostaPost = await fetch('http://localhost:3000/api/conteudos/criar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${meuToken}` },
            body: JSON.stringify({ titulo: "Minha Primeira Arte no PortArt", descricao: "Um desenho realista feito com grafite no papel Canson.", midia_url: "https://cloudinary.com/fotos/arte1.png" })
        });
        const dadosPost = await respostaPost.json();
        res.json({ resultadoDoPost: dadosPost });
    } catch (erro) { res.status(500).json({ erro: erro.message }); }
});

app.get('/api/ver-tudo', async (req, res) => {
    try {
        const users = await banco.query('SELECT id, nome, email FROM usuarios');
        const posts = await banco.query('SELECT * FROM conteudos');
        res.json({ usuariosNoBanco: users.rows, postsNoBanco: posts.rows });
    } catch (erro) { res.status(500).json({ erro: erro.message }); }
});

// =========================================================================
// 🚀 ROTA CORRIGIDA: LEITURA PÚBLICA DE CONTEÚDOS (GET)
// =========================================================================
app.get('/api/conteudos', async (req, res) => {
    try {
        const resultado = await banco.query(`
            SELECT 
                conteudos.id,
                conteudos.titulo,
                conteudos.descricao,
                conteudos.midia_url,
                conteudos.data_publicacao,
                usuarios.nome AS nome_artista
            FROM conteudos
            JOIN usuarios ON conteudos.usuario_id = usuarios.id
            ORDER BY conteudos.data_publicacao DESC
        `);

        res.json({
            status: "Sucesso",
            totalDePostagens: resultado.rows.length,
            postagens: resultado.rows
        });

    } catch (erro) {
        res.status(500).json({ 
            status: "Erro no banco de dados", 
            detalhe: erro.message 
        });
    }
}); // <-- O parêntese que faltava foi fechado bem aqui!

// Inicialização do Servidor
const PORT = 3000;
app.listen(PORT, () => { 
    console.log(`🚀 Servidor pronto na porta ${PORT}!`); 
});