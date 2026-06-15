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

// Configuração do seu Banco de Dados PostgreSQL
const banco = new Pool({
    user: 'postgres',          
    host: 'localhost',         
    database: 'portart_db',    
    password: '127869', // <-- Lembra de colocar sua senha do Postgres aqui!
    port: 5432,
    connectionTimeoutMillis: 5000 // Evita travamentos se o banco falhar
});

// Validar conexão com o banco
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

// MIDDLEWARE DE SEGURANÇA (Verificador de Crachá/Token JWT)
function conferirAutenticacao(req, res, next) {
    const cabecalhoAutenticacao = req.headers['authorization'];
    const token = cabecalhoAutenticacao && cabecalhoAutenticacao.split(' ')[1];

    if (!token) return res.status(401).json({ erro: "Acesso negado! Token ausente." });

    try {
        const dadosDoToken = jwt.verify(token, CHAVE_SECRETA_JWT);
        req.usuarioLogado = dadosDoToken; // Guarda os dados do usuário para as próximas rotas usarem
        next();
    } catch (erro) {
        return res.status(403).json({ erro: "Token inválido ou expirado!" });
    }
}

// Rota de Boas-Vindas
app.get('/', (req, res) => {
    res.send('Backend do PortArt Oficial Rodando de Forma Segura!');
});

// =========================================================================
// 👤 ROTA: CADASTRO DE USUÁRIOS (Gera Usuário + Preferências Iniciais)
// =========================================================================
app.post('/api/usuarios', async (req, res) => {
    const { nome, email, senha, bio } = req.body;
    
    if (!nome || !email || !senha) {
        return res.status(400).json({ erro: "Nome, e-mail e senha são obrigatórios!" });
    }

    try {
        // 1. Checa se o e-mail já existe
        const checarEmail = await banco.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (checarEmail.rows.length > 0) {
            return res.status(400).json({ erro: "Este e-mail já está cadastrado!" });
        }

        // 2. Criptografa a senha
        const senhaCriptografada = await bcrypt.hash(senha, 10);

        // 3. Salva o usuário na tabela 'usuarios'
        const novoUsuario = await banco.query(
            'INSERT INTO usuarios (nome, email, senha, bio) VALUES ($1, $2, $3, $4) RETURNING id, nome, email',
            [nome, email, senhaCriptografada, bio || 'Olá! Sou um artista no PortArt.']
        );

        const usuarioCriado = novoUsuario.rows[0];

        // 4. AUTOMAÇÃO: Cria as preferências visuais padrão do portfólio dele (1 para 1)
        await banco.query(
            'INSERT INTO preferencias_layout (usuario_id, cor_fundo, cor_acento, estilo_card) VALUES ($1, $2, $3, $4)',
            [usuarioCriado.id, '#FFFFFF', '#007BFF', 'moderno']
        );

        res.status(201).json({
            mensagem: "Usuário cadastrado com preferências criadas com sucesso!",
            usuario: usuarioCriado
        });

    } catch (erro) {
        res.status(500).json({ erro: "Erro ao cadastrar usuário: " + erro.message });
    }
});

// =========================================================================
// 🔑 ROTA: LOGIN (Autenticação JWT)
// =========================================================================
app.post('/api/auth/login', async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ erro: "Informe e-mail e senha!" });
    }

    try {
        const busca = await banco.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (busca.rows.length === 0) {
            return res.status(401).json({ erro: "E-mail ou senha incorretos!" });
        }

        const usuario = busca.rows[0];
        const senhaEstaCorreta = await bcrypt.compare(senha, usuario.senha);

        if (!senhaEstaCorreta) {
            return res.status(401).json({ erro: "E-mail ou senha incorretos!" });
        }

        // Gera o Token válido por 1 dia contendo o id e nome do artista
        const token = jwt.sign({ id: usuario.id, nome: usuario.nome }, CHAVE_SECRETA_JWT, { expiresIn: '1d' });

        res.json({
            mensagem: "Login efetuado com sucesso!",
            token: token,
            usuario: { id: usuario.id, nome: usuario.nome }
        });

    } catch (erro) {
        res.status(500).json({ erro: "Erro no servidor ao tentar logar: " + erro.message });
    }
});

// =========================================================================
// 🖼️ ROTA: CRIAR POST DE CONTEÚDO (POSTAGEM PROTEGIDA)
// =========================================================================
app.post('/api/conteudos/criar', conferirAutenticacao, async (req, res) => {
    const { titulo, descricao, midia_url } = req.body;
    const usuarioId = req.usuarioLogado.id; // Puxado automaticamente do Token seguro

    if (!titulo || !midia_url) {
        return res.status(400).json({ erro: "O título e a URL da mídia são obrigatórios!" });
    }

    try {
        const novoPost = await banco.query(
            'INSERT INTO conteudos (usuario_id, titulo, descricao, midia_url) VALUES ($1, $2, $3, $4) RETURNING *',
            [usuarioId, titulo, descricao, midia_url]
        );

        res.status(201).json({
            mensagem: "Publicação criada com sucesso no PortArt por " + req.usuarioLogado.nome,
            post: novoPost.rows[0]
        });

    } catch (erro) {
        res.status(500).json({ erro: "Erro ao salvar a postagem: " + erro.message });
    }
});

// =========================================================================
// 🌐 ROTA: VINCULAR REDE SOCIAL (PROTEGIDA)
// =========================================================================
app.post('/api/redes-sociais', conferirAutenticacao, async (req, res) => {
    const { nome_plataforma, perfil_url } = req.body;
    const usuarioId = req.usuarioLogado.id;

    if (!nome_plataforma || !perfil_url) {
        return res.status(400).json({ erro: "Informe a plataforma (ex: Instagram) e o link do perfil!" });
    }

    try {
        const novaRede = await banco.query(
            'INSERT INTO redes_sociais (usuario_id, nome_plataforma, perfil_url) VALUES ($1, $2, $3) RETURNING *',
            [usuarioId, nome_plataforma, perfil_url]
        );

        res.status(201).json({
            mensagem: `Rede social ${nome_plataforma} adicionada com sucesso ao perfil de ${req.usuarioLogado.nome}!`,
            redeSocial: novaRede.rows[0]
        });

    } catch (erro) {
        res.status(500).json({ erro: "Erro ao salvar rede social: " + erro.message });
    }
});

// =========================================================================
// 🚀 ROTA DE LEITURA PÚBLICA DE CONTEÚDOS (GET - Alimentar Feed do Dante)
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
        res.status(500).json({ status: "Erro ao buscar os conteúdos", detalhe: erro.message });
    }
});

// =========================================================================
// 🔍 ROTA DE INSPEÇÃO: VER TUDO (Útil para debugar no navegador)
// =========================================================================
app.get('/api/ver-tudo', async (req, res) => {
    try {
        const users = await banco.query('SELECT id, nome, email, bio FROM usuarios');
        const posts = await banco.query('SELECT * FROM conteudos');
        const layouts = await banco.query('SELECT * FROM preferencias_layout');
        const redes = await banco.query('SELECT * FROM redes_sociais');
        
        res.json({
            usuariosNoBanco: users.rows,
            postagensNoBanco: posts.rows,
            layoutsPersonalizados: layouts.rows,
            redesSociaisVinculadas: redes.rows
        });
    } catch (erro) {
        res.status(500).json({ erro: erro.message });
    }
});

// Inicialização do Servidor na porta 3000
const PORT = 3000;
app.listen(PORT, () => { 
    console.log(`🚀 Servidor pronto e rodando redondo na porta ${PORT}!`); 
});