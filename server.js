const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const app = express();
app.use(express.json());
app.use(cors());

const SECRET = "vt34554rgfedfnr3vfb3ehdsshufdsbhfbc4386=#$*%$667VFTC%$^%G^(Dv698879064cjabvc";
const HF_TOKEN = process.env.HF_TOKEN;
const db = new sqlite3.Database("./database.db");


// ===============================
// CRIAÇÃO DAS TABELAS
// ===============================
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS tarefas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    titulo TEXT NOT NULL,
    descricao TEXT,
    nota REAL,
    concluida INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
)`);


    db.run(`CREATE TABLE IF NOT EXISTS notas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        valor REAL
    )`);
});


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

    if (!username || !username.trim())
        return res.status(400).json({ erro: "Username obrigatório" });

    if (!password || password.length < 4)
        return res.status(400).json({ erro: "Senha muito curta" });

    const hash = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hash],
        function (err) {
            if (err)
                return res.status(400).json({ erro: "Usuário já existe" });

            res.json({ mensagem: "Usuário criado com sucesso" });
        }
    );
});


// ===============================
// LOGIN
// ===============================
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
            if (!user)
                return res.status(400).json({ erro: "Usuário não encontrado" });

            const senhaValida = await bcrypt.compare(password, user.password);
            if (!senhaValida)
                return res.status(400).json({ erro: "Senha incorreta" });

            const token = jwt.sign(
                { id: user.id },
                SECRET,
                { expiresIn: "1h" }
            );

            res.json({ mensagem: "Login realizado", token });
        }
    );
});


// ===============================
// CRIAR TAREFA
// ===============================
app.post("/tarefas", autenticar, (req, res) => {
    const { titulo, descricao, nota } = req.body;

    if (!titulo || !titulo.trim()) {
        return res.status(400).json({ erro: "Título obrigatório" });
    }

    const notaTratada =
        nota !== undefined && nota !== ""
            ? Number(nota)
            : null;

    db.run(
        "INSERT INTO tarefas (user_id, titulo, descricao, nota) VALUES (?, ?, ?, ?)",
        [req.userId, titulo, descricao || "", notaTratada],
        function (err) {
            if (err) {
                console.log("ERRO SQL:", err);
                return res.status(400).json({ erro: "Erro ao criar tarefa" });
            }

            res.json({ mensagem: "Tarefa criada com sucesso" });
        }
    );
});

// ===============================
// LISTAR TAREFAS
// ===============================
app.get("/tarefas", autenticar, (req, res) => {
    db.all(
        "SELECT * FROM tarefas WHERE user_id = ? ORDER BY id DESC",
        [req.userId],
        (err, rows) => {
            if (err)
                return res.status(400).json({ erro: "Erro ao buscar tarefas" });

            res.json(rows);
        }
    );
});


// ===============================
// ATUALIZAR TAREFA
// ===============================
app.put("/tarefas/:id", autenticar, (req, res) => {
    const { titulo, descricao, nota, concluida } = req.body;

    db.get(
        "SELECT * FROM tarefas WHERE id = ? AND user_id = ?",
        [req.params.id, req.userId],
        (err, tarefa) => {

            if (!tarefa)
                return res.status(404).json({ erro: "Tarefa não encontrada" });

            const novoTitulo = titulo !== undefined ? titulo : tarefa.titulo;
            const novaDescricao = descricao !== undefined ? descricao : tarefa.descricao;
            const novaNota = nota !== undefined ? nota : tarefa.nota;
            const novoStatus = concluida !== undefined ? (concluida ? 1 : 0) : tarefa.concluida;

            db.run(
                `UPDATE tarefas 
                 SET titulo = ?, descricao = ?, nota = ?, concluida = ?
                 WHERE id = ? AND user_id = ?`,
                [
                    novoTitulo,
                    novaDescricao,
                    novaNota,
                    novoStatus,
                    req.params.id,
                    req.userId
                ],
                function (err) {
                    if (err)
                        return res.status(400).json({ erro: "Erro ao atualizar tarefa" });

                    res.json({ mensagem: "Tarefa atualizada com sucesso" });
                }
            );
        }
    );
});

// ===============================
// EXCLUIR TAREFA
// ===============================
app.delete("/tarefas/:id", autenticar, (req, res) => {
    db.run(
        "DELETE FROM tarefas WHERE id = ? AND user_id = ?",
        [req.params.id, req.userId],
        function (err) {
            if (err)
                return res.status(400).json({ erro: "Erro ao excluir tarefa" });

            if (this.changes === 0)
                return res.status(404).json({ erro: "Tarefa não encontrada" });

            res.json({ mensagem: "Tarefa excluída com sucesso" });
        }
    );
});


// ===============================
// STATS
// ===============================
app.get("/stats", autenticar, (req, res) => {
    db.get(
        `SELECT 
            COUNT(*) as total,
            SUM(concluida) as concluidas
         FROM tarefas
         WHERE user_id = ?`,
        [req.userId],
        (err, row) => {
            if (err)
                return res.status(400).json({ erro: "Erro ao buscar stats" });

            res.json({
                total: row.total || 0,
                concluidas: row.concluidas || 0
            });
        }
    );
});


// ===============================
// RANKING
// ===============================
app.get("/ranking", (req, res) => {
    db.all(
        `SELECT 
            users.username,
            COALESCE(AVG(tarefas.nota), 0) as media
         FROM users
         LEFT JOIN tarefas 
            ON users.id = tarefas.user_id
         GROUP BY users.id
         ORDER BY media DESC`,
        (err, rows) => {
            if (err)
                return res.status(400).json({ erro: "Erro ao gerar ranking" });

            const rankingFormatado = rows.map(r => ({
                username: r.username,
                media: Number(r.media).toFixed(2)
            }));

            res.json(rankingFormatado);
        }
    );
});


// ===============================
// TESTE IA
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