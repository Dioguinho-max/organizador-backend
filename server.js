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

// ===============================
// FILTRO DE RESPOSTA DA IA
// ===============================
async function filtrarRespostaIA(texto) {
    if (!texto) return "";

    let textoLimpo = texto
        .replace(/\*\*/g, "")              // remove **
        .replace(/#/g, "")                 // remove #
        .replace(/---/g, "")               // remove ---
        .replace(/<br\s*\/?>/gi, "")       // remove <br>
        .replace(/\*/g, "")                // remove * solto
        .replace(/\n{3,}/g, "\n\n")        // evita muitas quebras
        .trim();

    // Limite de tamanho (evita resposta gigante)
    if (textoLimpo.length > 10000) {
        textoLimpo = textoLimpo.slice(0, 10000);
    }

    return textoLimpo;
}

//================================
// LIMITE IA
// ===============================
app.post("/gerar-plano", autenticar, async (req, res) => {
    const { materia, nivel, horas } = req.body;

    try {
        // Verificar se o usuário é admin
        const userResult = await pool.query(
            "SELECT is_admin FROM users WHERE id = $1",
            [req.userId]
        );
        const isAdmin = userResult.rows[0]?.is_admin;

        // Se não for admin, checar limite diário
        if (!isAdmin) {
            const countResult = await pool.query(
                `SELECT COUNT(*) as total
                 FROM historico_ia
                 WHERE user_id = $1
                 AND DATE(data) = CURRENT_DATE`,
                [req.userId]
            );

            if (countResult.rows[0].total >= 3) {
                return res.status(403).json({
                    erro: "Limite diário de 3 gerações atingido"
                });
            }
        }

        // Chamada à IA
        const response = await axios.post(
  "https://router.huggingface.co/v1/chat/completions",
  {
    model: "meta-llama/Meta-Llama-3-8B-Instruct",
    max_tokens: 775,
    temperature: 0.6,
    messages: [
      {
        role: "system",
        content: "Você é um tutor organizado e visual."
      },
      {
        role: "user",
        content: `Crie um plano de estudos para ${materia}, nível ${nivel}, estudando ${horas} horas por dia.
Regras:
- EXATAMENTE 4 semanas
- Use emojis
- Separador: ━━━━━━━━━━━━━━━━━━━
- Máximo 3 tópicos por semana
- Máximo 2 linhas por tópico
- Usar • no início
- Não usar markdown`
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

        const texto = response.data.choices[0].message.content;
        const textoFiltrado = await filtrarRespostaIA(texto);

        // Salvar historico
        await pool.query(
            "INSERT INTO historico_ia (user_id, pergunta, resposta) VALUES ($1, $2, $3)",
            [req.userId, `Plano para ${materia}`, textoFiltrado]
        );

        res.json({ plano: textoFiltrado });

    } catch (error) {
        console.error(error.response?.data || error.message);
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
        model: "meta-llama/Meta-Llama-3-8B-Instruct",
        max_tokens: 300,
        temperature: 0.5,
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

    res.json({
      resposta: response.data.choices[0].message.content
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
