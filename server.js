const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();

// Moteur de vues EJS, fichiers .ejs à la racine du projet
app.set('view engine', 'ejs');
app.set('views', __dirname); // important pour Render

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname))); // pour style.css

// Session (clé simple pour test, à changer si prod)
app.use(session({
  secret: 'damibook-secret',
  resave: false,
  saveUninitialized: false
}));

// Connexion MongoDB (mets ici ton URI ou utilise process.env.MONGO_URL)
const MONGO_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/damibook';
mongoose.connect(MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('MongoDB connected');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// Schéma utilisateur simple
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String
});

const User = mongoose.model('User', userSchema);

// Middleware pour protéger les pages
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

// Routes
app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.render('login', { error: 'Utilisateur introuvable' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render('login', { error: 'Mot de passe incorrect' });
    }
    req.session.userId = user._id;
    res.redirect('/home');
  } catch (err) {
    console.error(err);
    res.status(500).send('Erreur serveur');
  }
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashed });
    await user.save();
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.status(500).send('Erreur serveur');
  }
});

app.get('/home', requireLogin, (req, res) => {
  res.render('home');
});

app.get('/chat', requireLogin, (req, res) => {
  res.render('chat');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Port pour Render
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
