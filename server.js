const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const { Pool } = require('pg'); 
const jwt = require('jsonwebtoken'); 
// Configuração do Multer para gerenciar upload de arquivos locais
const multer = require('multer');
const path = require('path');

// 1. PRIMEIRO INICIAMOS O APP DO EXPRESS
const app = express();

// 2. CONFIGURAÇÃO DO STORAGE DO MULTER
const configuracaoArmazenamento = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Os arquivos salvos vão para uma pasta chamada 'uploads'
    },
    filename: (req, file, cb) => {
        // Renomeia o arquivo para evitar que nomes duplicados se sobrescrevam
        const sufixoUnico = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, sufixoUnico + path.extname(file.originalname));
    }
});

const upload = multer({ storage: configuracaoArmazenamento });

// 3. AGORA AS MIDDLEWARES CONSEGUEM USAR O 'APP' SEM DAR ERRO
app.use('/uploads', express.static('uploads'));
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

// FUNÇÃO AUXILIAR: Validador de Formato de E-mail
function emailValido(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

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
    
    // 1. Validação de campos obrigatórios
    if (!nome || !email || !senha) {
        return res.status(400).json({ erro: "Nome, e-mail e senha são obrigatórios!" });
    }

    // 2. Validação do formato do e-mail
    if (!emailValido(email)) {
        return res.status(400).json({ erro: "O formato do e-mail informado é inválido!" });
    }

    // 3. Validação do tamanho da senha (mínimo 6 caracteres para segurança do artista)
    if (senha.length < 6) {
        return res.status(400).json({ erro: "A senha deve ter no mínimo 6 caracteres!" });
    }

    try {
        // Checa se o e-mail já existe
        const checarEmail = await banco.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (checarEmail.rows.length > 0) {
            return res.status(400).json({ erro: "Este e-mail já está cadastrado!" });
        }

        // Criptografa a senha
        const senhaCriptografada = await bcrypt.hash(senha, 10);

        // Salva o usuário na tabela 'usuarios'
        const novoUsuario = await banco.query(
            'INSERT INTO usuarios (nome, email, senha, bio) VALUES ($1, $2, $3, $4) RETURNING id, nome, email',
            [nome, email, senhaCriptografada, bio || 'Olá! Sou um artista no PortArt.']
        );

        const usuarioCriado = novoUsuario.rows[0];

        // AUTOMAÇÃO: Cria as preferências visuais padrão do portfólio dele (1 para 1)
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
// 🖼️ ROTA: CRIAR POST DE CONTEÚDO (POSTAGEM PROTEGIDA COM UPLOAD REAL)
// =========================================================================
app.post('/api/conteudos/criar', conferirAutenticacao, upload.single('imagem'), async (req, res) => {
    const { titulo, descricao } = req.body;
    const usuarioId = req.usuarioLogado.id;

    // Se o usuário mandou um arquivo físico, usamos o caminho dele. Se não mandou, checa se veio uma URL por texto.
    let urlFinalDaMidia = req.file ? `/uploads/${req.file.filename}` : req.body.midia_url;

    if (!titulo || !urlFinalDaMidia) {
        return res.status(400).json({ erro: "O título e o arquivo de imagem (ou URL) são obrigatórios!" });
    }

    try {
        const novoPost = await banco.query(
            'INSERT INTO conteudos (usuario_id, titulo, descricao, midia_url) VALUES ($1, $2, $3, $4) RETURNING *',
            [usuarioId, titulo, descricao, urlFinalDaMidia]
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
// 🎨 ROTA: ATUALIZAR PREFERÊNCIAS DE LAYOUT (PROTEGIDA)
// =========================================================================
app.put('/api/preferencias-layout', conferirAutenticacao, async (req, res) => {
    const { cor_fundo, cor_acento, estilo_card } = req.body;
    const usuarioId = req.usuarioLogado.id; // Pega o ID do artista direto do token seguro

    // Validação básica opcional para garantir integridade dos dados
    if (cor_fundo && cor_fundo.length !== 7) {
        return res.status(400).json({ erro: "A cor de fundo deve ser um código hexadecimal válido (ex: #FFFFFF)!" });
    }
    if (cor_acento && cor_acento.length !== 7) {
        return res.status(400).json({ erro: "A cor de acento deve ser um código hexadecimal válido (ex: #007BFF)!" });
    }

    try {
        // Aktualiza os registros baseados no ID do usuário logado
        const layoutAtualizado = await banco.query(
            `UPDATE preferencias_layout 
             SET cor_fundo = COALESCE($1, cor_fundo), 
                 cor_acento = COALESCE($2, cor_acento), 
                 estilo_card = COALESCE($3, estilo_card)
             WHERE usuario_id = $4 RETURNING *`,
            [cor_fundo, cor_acento, estilo_card, usuarioId]
        );

        if (layoutAtualizado.rows.length === 0) {
            return res.status(404).json({ erro: "Configurações de layout não encontradas para este usuário." });
        }

        res.json({
            mensagem: "Visual do portfólio updated com sucesso!",
            layout: layoutAtualizado.rows[0]
        });

    } catch (erro) {
        res.status(500).json({ erro: "Erro ao atualizar preferências de layout: " + erro.message });
    }
});

// =========================================================================
// ✏️ ROTA: EDITAR POSTAGEM DE CONTEÚDO (PROTEGIDA)
// =========================================================================
app.put('/api/conteudos/:id', conferirAutenticacao, async (req, res) => {
    const idPost = req.params.id; // Pega o ID do post vindo na URL (ex: /api/conteudos/5)
    const { titulo, descricao, midia_url } = req.body;
    const usuarioId = req.usuarioLogado.id; // ID do usuário vindo do token seguro

    try {
        // Primeiro, atualiza o post APENAS se ele pertencer ao usuário logado
        const postAtualizado = await banco.query(
            `UPDATE conteudos 
             SET titulo = COALESCE($1, titulo),
                 descricao = COALESCE($2, descricao),
                 midia_url = COALESCE($3, midia_url)
             WHERE id = $4 AND usuario_id = $5 RETURNING *`,
            [titulo, descricao, midia_url, idPost, usuarioId]
        );

        // Se não retornou nenhuma linha, ou o post não existe ou não pertence a quem está logado
        if (postAtualizado.rows.length === 0) {
            return res.status(403).json({ erro: "Ação não autorizada ou postagem não encontrada!" });
        }

        res.json({
            mensagem: "Publicação editada com sucesso!",
            post: postAtualizado.rows[0]
        });

    } catch (erro) {
        res.status(500).json({ erro: "Erro ao editar postagem: " + erro.message });
    }
});

// =========================================================================
// ❤️ ROTA: CURTIR / REMOVER CURTIDA DE UMA ARTE (PROTEGIDA)
// =========================================================================
app.post('/api/conteudos/:id/curtir', conferirAutenticacao, async (req, res) => {
    const idPost = req.params.id;
    const usuarioId = req.usuarioLogado.id;

    try {
        // 1. Verifica se a publicação de fato existe
        const postExiste = await banco.query('SELECT id FROM conteudos WHERE id = $1', [idPost]);
        if (postExiste.rows.length === 0) {
            return res.status(404).json({ erro: "Publicação não encontrada!" });
        }

        // 2. Checa se o usuário já curtiu esse post antes
        const jaCurtiu = await banco.query(
            'SELECT id FROM curtidas WHERE usuario_id = $1 AND conteudo_id = $2',
            [usuarioId, idPost]
        );

        if (jaCurtiu.rows.length > 0) {
            // Se já curtiu, a gente remove a curtida (efeito toggle/descurtir)
            await banco.query(
                'DELETE FROM curtidas WHERE usuario_id = $1 AND conteudo_id = $2',
                [usuarioId, idPost]
            );
            return res.json({ mensagem: "Curtida removida com sucesso!" });
        } else {
            // Se não curtiu ainda, adiciona no banco
            await banco.query(
                'INSERT INTO curtidas (usuario_id, conteudo_id) VALUES ($1, $2)',
                [usuarioId, idPost]
            );
            return res.status(201).json({ mensagem: "Publicação curtida com sucesso!" });
        }

    } catch (erro) {
        res.status(500).json({ erro: "Erro ao processar curtida: " + erro.message });
    }
});

// =========================================================================
// 🗑️ ROTA: DELETAR POSTAGEM DE CONTEÚDO (PROTEGIDA)
// =========================================================================
app.delete('/api/conteudos/:id', conferirAutenticacao, async (req, res) => {
    const idPost = req.params.id;
    const usuarioId = req.usuarioLogado.id;

    try {
        // Deleta o post APENAS se o id coincidir e pertencer ao criador
        const resultadoDelecao = await banco.query(
            'DELETE FROM conteudos WHERE id = $1 AND usuario_id = $2 RETURNING *',
            [idPost, usuarioId]
        );

        if (resultadoDelecao.rows.length === 0) {
            return res.status(403).json({ erro: "Ação não autorizada ou postagem não encontrada!" });
        }

        res.json({
            mensagem: "Publicação removida com sucesso do PortArt!"
        });

    } catch (erro) {
        res.status(500).json({ erro: "Erro ao deletar postagem: " + erro.message });
    }
});

// =========================================================================
// 🚀 ROTA DE LEITURA PÚBLICA DE CONTEÚDOS COM PAGINAÇÃO E LIKES
// =========================================================================
app.get('/api/conteudos', async (req, res) => {
    const pagina = parseInt(req.query.pagina) || 1;
    const limitePorPagina = 10; 
    const quantidadeParaPular = (pagina - 1) * limitePorPagina;

    try {
        const totalQuery = await banco.query('SELECT COUNT(*) FROM conteudos');
        const totalDePostagens = parseInt(totalQuery.rows[0].count);

        const resultado = await banco.query(`
            SELECT 
                conteudos.id,
                conteudos.titulo,
                conteudos.descricao,
                conteudos.midia_url,
                conteudos.data_publicacao,
                usuarios.nome AS nome_artista,
                COUNT(curtidas.id)::INTEGER AS total_curtidas
            FROM conteudos
            JOIN usuarios ON conteudos.usuario_id = usuarios.id
            LEFT JOIN curtidas ON conteudos.id = curtidas.conteudo_id
            GROUP BY conteudos.id, usuarios.nome
            ORDER BY conteudos.data_publicacao DESC
            LIMIT $1 OFFSET $2
        `, [limitePorPagina, quantidadeParaPular]);

        const totalPaginas = Math.ceil(totalDePostagens / limitePorPagina);

        res.json({
            status: "Sucesso",
            paginacao: {
                paginaAtual: pagina,
                totalPaginas: totalPaginas,
                totalItens: totalDePostagens,
                itensPorPagina: limitePorPagina
            },
            postagens: resultado.rows
        });

    } catch (erro) {
        res.status(500).json({ status: "Erro ao buscar os conteúdos", detalhe: erro.message });
    }
});

// =========================================================================
// 🔍 ROTA: BUSCAR PERFIL COMPLETO DO ARTISTA (PÚBLICA - Para o Portfólio)
// =========================================================================
app.get('/api/usuarios/:id', async (req, res) => {
    const idArtista = req.params.id;

    try {
        // 1. Busca os dados públicos básicos do artista
        const usuarioQuery = await banco.query(
            'SELECT id, nome, bio, data_criacao FROM usuarios WHERE id = $1',
            [idArtista]
        );

        if (usuarioQuery.rows.length === 0) {
            return res.status(404).json({ erro: "Artista não encontrado no PortArt!" });
        }

        const artista = usuarioQuery.rows[0];

        // 2. Busca as preferências de layout dele (cores e estilo)
        const layoutQuery = await banco.query(
            'SELECT cor_fundo, cor_acento, estilo_card FROM preferencias_layout WHERE usuario_id = $1',
            [idArtista]
        );

        // 3. Busca as redes sociais vinculadas por ele
        const redesQuery = await banco.query(
            'SELECT id, nome_plataforma, perfil_url FROM redes_sociais WHERE usuario_id = $1',
            [idArtista]
        );

        // 4. Busca todas as publicações/artes desse artista específico (Atualizado com total_curtidas!)
        const conteudosQuery = await banco.query(`
            SELECT 
                conteudos.id, 
                conteudos.titulo, 
                conteudos.descricao, 
                conteudos.midia_url, 
                conteudos.data_publicacao,
                COUNT(curtidas.id)::INTEGER AS total_curtidas
            FROM conteudos 
            LEFT JOIN curtidas ON conteudos.id = curtidas.conteudo_id
            WHERE conteudos.usuario_id = $1 
            GROUP BY conteudos.id
            ORDER BY conteudos.data_publicacao DESC
        `, [idArtista]);

        res.json({
            status: "Sucesso",
            artista: artista,
            layout: layoutQuery.rows[0] || { cor_fundo: "#FFFFFF", cor_acento: "#007BFF", estilo_card: "moderno" }, 
            redesSociais: redesQuery.rows,
            postagens: conteudosQuery.rows
        });

    } catch (erro) {
        console.error("Erro ao buscar perfil do artista:", erro);
        res.status(500).json({ erro: "Erro interno no servidor ao montar o perfil: " + erro.message });
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