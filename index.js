const express = require('express')
const bodyParser = require('body-parser')
const speakeasy = require('speakeasy')
const qrcode = require('qrcode')
const {JsonDB} = require('node-json-db')
const {Config} = require('node-json-db/dist/lib/JsonDBConfig')
const nunjucks = require('nunjucks')
const session = require('express-session')
const cryptoJs = require('crypto-js')
const app = express()
const port = 5000

app.use(session({
    secret: 'supersecret',
}))
app.use(express.static(__dirname + '/'));

const db = new JsonDB('myDatabase')
db.load(() =>{
    const db = new JsonDB(new Config('myDatabase', true, false, '/'))
})

app.listen(port, () =>{
    console.log(`2FA Node app listening at http://localhost:${port}`)
})

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
nunjucks.configure('views',{express: app})

app.get('/', (req, res) => {
    // res.render('index.html')
    res.render('login.html')
})
app.get('/register', (req, res) => {
    res.render('register.html')
})

//register user & create temp secret
app.post('/register', (req, res) => {
    var user = req.body.user
    var passw = req.body.passw
    var verified = registerVerify(user,passw, res)
    if(verified){
        const passwEncr = cryptoJs.MD5(passw)
        const path = `/user/${user}`
        if(!db.exists(path)){
            var autenticator = req.body.auth_checkbox;
            if(autenticator === 'true'){
                try {
                    const temp_secret = speakeasy.generateSecret({
                        name: `Prueba con ${user}`
                    })
                    // res.json({id, secret: temp_secret.base32})
                    qrcode.toDataURL(temp_secret.otpauth_url, function (err, data_url){
                        if (err){
                            throw err
                        }
                        req.session.qr = data_url
                        req.session.user = user
                        db.push(path, {user, passw, temp_secret})
                        res.redirect('/qrGenerator')
                    })

                }catch (error){
                    res.status(500).json({message: 'Error generating the secret'})
                }
            }
            else{
                req.session.user = user
                db.push(path, {user, passw})
                res.redirect('/page')
            }
        }
        else {
            res.render('register.html', {userWarnings: "Ese usuario ya está en uso"})
        }
    }
})

app.get('/qrGenerator', (req, res) => {
    if(!req.session.qr){
        return res.redirect('/')
    }
    return res.render('qrGenerator.html', {qr: req.session.qr})
})

app.post('/verify', (req, res) => {
    var userId = req.session.user
    var token = req.body.auth_code
    try {
        // Retrieve user from database
        const path = `/user/${userId}`
        const user = db.getData(path)
        const { base32: secret } = user.temp_secret
        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token
        });

        if (verified){
            req.session.verify = true;
            return res.redirect('/page')
        }
        else{
            res.render('qrGenerator.html', {qr: req.session.qr, warnings: "El código no es correcto"})
        }
    }catch (error){
        res.render('login.html', {warnings: "Error en el usuario"})
    }
})

app.post('/verifyCode', (req, res) => {
    var userId = req.session.user
    var token = req.body.auth_code
    try {
        // Retrieve user from database
        const path = `/user/${userId}`
        const user = db.getData(path)
        const { base32: secret } = user.temp_secret
        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token
        });

        if (verified){
            req.session.verify = true;
            return res.redirect('/page')
        }
        else{
            res.render('validarCodigo.html', {warnings: "El código no es correcto"})
        }
    }catch (error){
        res.render('login.html', {warnings: "Error en el usuario"})
    }
})

app.get('/page', (req, res) => {
    if(req.session.user && req.session.verify){
        return res.render('page.html', {user: req.session.user})
    }
    return res.redirect('/')
})

app.get('/validarCodigo', (req, res) => {
    res.render('validarCodigo.html')
})

app.post('/login', (req, res) => {
    var user = req.body.user
    var passw = req.body.passw
    var verified = loginVerify(user,passw, res)
    if(verified){
        try{
            const path = `/user/${user}`
            var dbUser = db.getData(path)
            var secret  = dbUser.temp_secret
            if(passw === dbUser.passw){
                req.session.user = user
                if(secret !== undefined){
                    qrcode.toDataURL(secret.otpauth_url, function (err, data_url){
                        if (err){
                            throw err
                        }
                        req.session.qr = data_url
                        res.redirect('/validarCodigo')
                    })
                }
                else{
                    res.redirect('/page')
                }
            }
            else {
                res.render('login.html', {warnings: "La contraseña y el usuario no coinciden"})
            }
        }catch (error){
            res.render('login.html', {warnings: "El usuario no está registrado en la base de datos"})
            // res.status(500).json({message: 'Usuario no encontrado'})
        }
    }

})
app.post('/logOut', (req, res) => {
    req.session.destroy()
    return res.redirect('/')
})

function loginVerify(user, passw, res){
    var userWarnings = ""
    var passwWarnings = ""
    var modificar = false

    if(user.length < 1){
        userWarnings += 'El campo del nombre no puede estar vacío'
        modificar = true
    }
    if(passw.length < 1){
        passwWarnings += 'El campo de la password no puede estar vacía'
        modificar = true
    }

    if (modificar){
        res.render('login.html', {userWarnings: userWarnings, passwWarnings: passwWarnings})
        return false;
    }

    return true;
}

function registerVerify(user, passw, res){
    var userWarnings = ""
    var passwWarnings = ""
    var modificar = false

    if(user.length < 1){
        userWarnings += 'El campo del nombre no puede estar vacío'
        modificar = true
    }
    if(passw.length < 1){
        passwWarnings += 'El campo de la password no puede estar vacía'
        modificar = true
    }
    else if(passw.length >= 8){
        if(!passw.match(/\d/) && !passw.match(/[A-Z]/)){
            passwWarnings += 'La contraseña debe tener mínimo una mayuscula y un carácter numérico'
            modificar = true
        }else{
            if(!passw.match(/\d/)){
                passwWarnings += 'La contraseña debe tener mínimo un carácter numérico'
                modificar = true
            }
            else if(!passw.match(/[A-Z]/)){
                passwWarnings += 'La contraseña debe tener mínimo una mayuscula'
                modificar = true
            }
        }
    } else {
        passwWarnings += 'La contraseña debe tener mínimo 8 caracteres'
        modificar = true
    }

    if (modificar){
        res.render('register.html', {userWarnings: userWarnings, passwWarnings: passwWarnings})
        return false;
    }

    return true;
}
