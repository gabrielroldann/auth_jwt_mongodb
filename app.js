require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Configurando JSON response
app.use(express.json());

// Models
const User = require('./models/User');

// Public Route
app.get('/', (req, res) => {
    res.status(200).json({msg: "Conectado a API"})
});

// Private Route
app.get('/user/:id', checkToken, async(req, res) => {

    const id = req.params.id;

    //user existe
    const user = await User.findById(id, '-password');

    if (!user) {
        return res.status(404).json({msg: "Usuário não encontrado"});
    }

    res.status(200).json({ user })
});

function checkToken( req, res, next ) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1];

    if(!token) {
        return res.status(401).json({ msg: "Acesso negado" })
    }

    try {
        
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch(error) {
        res.status(400).json({ msg: "Token inválido" })
    }
}

// Register User
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmPassword} = req.body;

    // validação
    if (!name) {
        return res.status(422).json({msg: "O nome é obrigatório"})
    }
    if (!email) {
        return res.status(422).json({msg: "O email é obrigatório"})
    }
    if (!password) {
        return res.status(422).json({msg: "A senha é obrigatória"})
    }
    if (password !== confirmPassword) {
        return res.status(422).json({msg: "As senhas não conferem."})
    }

    // user existe
    const userExists = await User.findOne({ email: email })

    if (userExists) {
        return res.status(422).json({msg: "Email já registrado"})
    }

    // criando password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // criando user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {

        await user.save();

        res.status(201).json({msg: "Usuário criado com sucesso"})
    } catch (error) {

        res.status(500).json({msg: error})
    }
});

// login user 
app.post('/auth/login', async(req, res) => {
    const { email, password } = req.body;

    if (!email) {
        return res.status(422).json({msg: "O email é obrigatório"})
    }
    if (!password) {
        return res.status(422).json({msg: "A senha é obrigatória"})
    }

    // user existe
    const user = await User.findOne({ email: email })

    if (!user) {
        return res.status(404).json({msg: "Usuário não encontrado"});
    }

    // validando password
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({msg: "Senha incorreta"});
    }

    try {

        const secret = process.env.secret

        const token = jwt.sign({
            id: user._id,
        }, secret)

        res.status(200).json({msg: "Logado com sucesso", token})
    } catch (err) {
        console.log(err);
        res.status(500).json({msg: err});
    }
})

// delete user
app.delete('/auth/delete', async(req, res) => {

});

// conectando ao banco
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS
mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.yho4oew.mongodb.net/`)
    .then(() => {
        app.listen(3000);
        console.log('Conectou ao Banco!');
    })
    .catch((err) => console.log(err))
