const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const app = express();
app.use(express.json());
app.use(cors());

const SECRET = process.env.JWT_SECRET;
const HF_TOKEN = process.env.HF_TOKEN;
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// ===============================
// CRIAÇÃO DAS TABELAS
// ===============================
async function criarTabelas() {
    await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        is_admin BOOLEAN DEFAULT FALSE
    );
`);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS tarefas (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            titulo TEXT NOT NULL,
            descricao TEXT,
            nota REAL,
            concluida INTEGER DEFAULT 0
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS historico_ia (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            pergunta TEXT,
            resposta TEXT,
            data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);

    console.log("Tabelas criadas 🚀");
}

criarTabelas();

// ===============================
// MIDDLEWARE JWT
// ===============================
function autenticar(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader)
        return res.status(403).json({ erro: "Token necessário" });

    const token = authHeader.split(" ")[1];

    jwt.verify(token, SECRET, (err, decoded) => {
        if (err)
            return res.status(403).json({ erro: "Token inválido" });

        req.userId = decoded.id;
        next();
    });
}

//==================
//limpar texto ia
//==================
function limparTextoIA(texto) {
    texto = texto
        .replace(/[*#`_~]/g, "")
        .replace(/---/g, "")
        .replace(/[•►–]/g, "")
        .trim();

    const emojiRegex = /([\u{1F300}-\u{1FAFF}])/gu;
    const emojis = texto.match(emojiRegex);

    if (emojis && emojis.length > 2) {
        let count = 0;
        texto = texto.replace(emojiRegex, (match) => {
            count++;
            return count <= 2 ? match : "";
        });
    }

    return texto;
}

// ===============================
// REGISTER
// ===============================
app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password)
        return res.status(400).json({ erro: "Dados inválidos" });

    const hash = await bcrypt.hash(password, 10);

    try {
        await pool.query(
            "INSERT INTO users (username, password) VALUES ($1, $2)",
            [username, hash]
        );

        res.json({ mensagem: "Usuário criado com sucesso" });

    } catch (err) {
        res.status(400).json({ erro: "Usuário já existe" });
    }
});


// ===============================
// LOGIN
// ===============================
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    const result = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
    );

    const user = result.rows[0];

    if (!user)
        return res.status(400).json({ erro: "Usuário não encontrado" });

    const senhaValida = await bcrypt.compare(password, user.password);

    if (!senhaValida)
        return res.status(400).json({ erro: "Senha incorreta" });

    const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: "1h" });

    res.json({ token });
});


// ===============================
// CRIAR TAREFA
// ===============================
app.post("/tarefas", autenticar, async (req, res) => {
    const { titulo, descricao, nota } = req.body;

    await pool.query(
        "INSERT INTO tarefas (user_id, titulo, descricao, nota) VALUES ($1, $2, $3, $4)",
        [req.userId, titulo, descricao || "", nota || null]
    );

    res.json({ mensagem: "Tarefa criada" });
});
// ===============================
// LISTAR TAREFAS
// ===============================
app.get("/tarefas", autenticar, async (req, res) => {
    const result = await pool.query(
        "SELECT * FROM tarefas WHERE user_id = $1 ORDER BY id DESC",
        [req.userId]
    );

    res.json(result.rows);
});

// ===============================
// ATUALIZAR TAREFA
// ===============================
app.put("/tarefas/:id", autenticar, async (req, res) => {
    const { titulo, descricao, nota, concluida } = req.body;

    const result = await pool.query(
        "SELECT * FROM tarefas WHERE id = $1 AND user_id = $2",
        [req.params.id, req.userId]
    );

    const tarefa = result.rows[0];

    if (!tarefa)
        return res.status(404).json({ erro: "Tarefa não encontrada" });

    await pool.query(
        `UPDATE tarefas 
         SET titulo = $1, descricao = $2, nota = $3, concluida = $4
         WHERE id = $5 AND user_id = $6`,
        [
            titulo ?? tarefa.titulo,
            descricao ?? tarefa.descricao,
            nota ?? tarefa.nota,
            concluida !== undefined ? (concluida ? 1 : 0) : tarefa.concluida,
            req.params.id,
            req.userId
        ]
    );

    res.json({ mensagem: "Tarefa atualizada com sucesso" });
});

// ===============================
// EXCLUIR TAREFA
// ===============================
app.delete("/tarefas/:id", autenticar, async (req, res) => {
    const result = await pool.query(
        "DELETE FROM tarefas WHERE id = $1 AND user_id = $2",
        [req.params.id, req.userId]
    );

    if (result.rowCount === 0)
        return res.status(404).json({ erro: "Tarefa não encontrada" });

    res.json({ mensagem: "Tarefa excluída" });
});


// ===============================
// STATS
// ===============================
app.get("/stats", autenticar, async (req, res) => {
    const result = await pool.query(
        `SELECT 
            COUNT(*) as total,
            COALESCE(SUM(concluida),0) as concluidas
         FROM tarefas
         WHERE user_id = $1`,
        [req.userId]
    );

    res.json(result.rows[0]);
});

// ===============================
// RANKING
// ===============================
app.get("/ranking", async (req, res) => {
    const result = await pool.query(`
        SELECT 
            users.username,
            COALESCE(AVG(tarefas.nota), 0) as media
        FROM users
        LEFT JOIN tarefas 
            ON users.id = tarefas.user_id
        GROUP BY users.id
        ORDER BY media DESC
    `);

    const rankingFormatado = result.rows.map(r => ({
        username: r.username,
        media: Number(r.media).toFixed(2)
    }));

    res.json(rankingFormatado);
});

//================================
// LIMITE IA
// ===============================
app.post("/gerar-plano", autenticar, async (req, res) => {
    const { materia, nivel, horas } = req.body;

    try {
        const userResult = await pool.query(
            "SELECT is_admin FROM users WHERE id = $1",
            [req.userId]
        );
        const isAdmin = userResult.rows[0]?.is_admin;

        if (!isAdmin) {
            const countResult = await pool.query(
                `SELECT COUNT(*) as total
                 FROM historico_ia
                 WHERE user_id = $1
                 AND DATE(data) = CURRENT_DATE`,
                [req.userId]
            );

            if (parseInt(countResult.rows[0].total) >= 3) {
                return res.status(403).json({
                    erro: "Limite diário de 3 gerações atingido"
                });
            }
        }

        const response = await axios.post(
    "https://router.huggingface.co/v1/chat/completions",
    {
        model: "mistralai/Mistral-7B-Instruct-v0.2",
        messages: [
            {
                role: "system",
                content: `
Você é um tutor didático e direto.

Responda em duas partes:

PARTE 1 - EXPLICAÇÃO:
Explique em até 8 linhas por que esse plano funciona.

PARTE 2 - PLANO:
Liste tarefas simples.
Cada linha deve começar com Dia X:
Não use markdown.
Não use símbolos decorativos.
Texto simples.
Máximo total: 20 linhas.
`
            },
            {
                role: "user",
                content: `Crie um plano de estudos para ${materia}, nível ${nivel}, estudando ${horas} horas por dia.`
            }
        ],
        max_tokens: 700,
        temperature: 0.6
    },
    {
        headers: {
            Authorization: `Bearer ${HF_TOKEN}`,
            "Content-Type": "application/json"
        }
    }
);

let texto = response.data.choices[0].message.content;
texto = limparTextoIA(texto);


        await pool.query(
            "INSERT INTO historico_ia (user_id, pergunta, resposta) VALUES ($1, $2, $3)",
            [req.userId, `Plano para ${materia}`, texto]
        );

        res.json({ plano: texto });

    } catch (error) {
        console.error("Erro Hugging Face:", error.response?.data || error.message);
        res.status(500).json({ erro: "Erro ao gerar plano" });
    }
});

//===============================
// HISTORICO IA
//===============================
app.get("/historico-ia", autenticar, async (req, res) => {
    const result = await pool.query(
        "SELECT * FROM historico_ia WHERE user_id = $1 ORDER BY data DESC",
        [req.userId]
    );

    res.json(result.rows);
});

//================================
// IA
// ===============================
app.get("/teste-ia", async (req, res) => {
    try {
        const response = await axios.post(
            "https://router.huggingface.co/v1/chat/completions",
            {
                model: "mistralai/Mistral-7B-Instruct-v0.2",
                messages: [
                    {
                        role: "system",
                        content: "Você é um tutor especialista em estudos."
                    },
                    {
                        role: "user",
                        content: "Crie um plano simples para estudar matemática para iniciantes."
                    }
                ]
            },
            {
                headers: {
                    Authorization: `Bearer ${process.env.HF_TOKEN}`,
                    "Content-Type": "application/json"
                }
            }
        );

        let texto = response.data.choices[0].message.content;

// Remove markdown
texto = texto
    .replace(/[*#`_~]/g, "")
    .replace(/---/g, "")
    .trim();

// Limitar emojis (máximo 2)
const emojiRegex = /([\u{1F300}-\u{1FAFF}])/gu;
const emojis = texto.match(emojiRegex);

if (emojis && emojis.length > 2) {
    let count = 0;
    texto = texto.replace(emojiRegex, (match) => {
        count++;
        return count <= 2 ? match : "";
    });
}
res.json({
    resposta: texto,
});
        

    } catch (error) {
        console.error("Erro Hugging Face:", error.response?.data || error.message);
        res.status(500).json({
            erro: error.response?.data || error.message
        });
    }
});

// ===============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Servidor rodando 🚀");
});
