const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();

// ====== CONFIG ======
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'damibook-secret',
  resave: false,
  saveUninitialized: false
}));

// ====== MONGODB ======
// En local : mongodb://127.0.0.1:27017/damibook
// En prod (plus tard) : utiliser process.env.MONGODB_URI
const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/damibook';

mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('MongoDB connecté');
}).catch(err => {
  console.error('Erreur MongoDB', err);
});

// ====== MODELES ======
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  createdAt: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);

const postSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  createdAt: { type: Date, default: Date.now }
});

const Post = mongoose.model('Post', postSchema);

const commentSchema = new mongoose.Schema({
  post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  createdAt: { type: Date, default: Date.now }
});

const Comment = mongoose.model('Comment', commentSchema);

// ====== MIDDLEWARE AUTH ======
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

// ====== ROUTES ======

// Page d'accueil (protégée) : publications + autres utilisateurs
app.get('/', requireLogin, async (req, res) => {
  const user = await User.findById(req.session.userId);
  const others = await User.find({ _id: { $ne: user._id } });

  const posts = await Post.find({})
    .sort({ createdAt: -1 })
    .populate('author');

  const comments = await Comment.find({})
    .sort({ createdAt: 1 })
    .populate('author')
    .populate('post');

  res.render('home', { user, others, posts, comments });
});

// Page login
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Traitement login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user) {
    return res.render('login', { error: 'Utilisateur introuvable' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.render('login', { error: 'Mot de passe incorrect' });
  }

  req.session.userId = user._id;
  res.redirect('/');
});

// Page inscription
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// Traitement inscription
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.render('register', { error: 'Pseudo et mot de passe obligatoires' });
  }

  const existing = await User.findOne({ username });
  if (existing) {
    return res.render('register', { error: 'Ce pseudo est déjà pris' });
  }

  const hash = await bcrypt.hash(password, 10);
  const user = new User({
    username,
    passwordHash: hash
  });
  await user.save();

  req.session.userId = user._id;
  res.redirect('/');
});

// Déconnexion
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Page de chat privé avec un autre utilisateur
app.get('/chat/:userId', requireLogin, async (req, res) => {
  const me = await User.findById(req.session.userId);
  const other = await User.findById(req.params.userId);

  if (!other) {
    return res.redirect('/');
  }

  const messages = await Message.find({
    $or: [
      { from: me._id, to: other._id },
      { from: other._id, to: me._id }
    ]
  }).sort({ createdAt: 1 }).populate('from to');

  res.render('chat', { me, other, messages });
});

// Envoi d'un message privé
app.post('/chat/:userId', requireLogin, async (req, res) => {
  const me = await User.findById(req.session.userId);
  const other = await User.findById(req.params.userId);

  if (!other) {
    return res.redirect('/');
  }

  const { content } = req.body;
  if (!content || !content.trim()) {
    return res.redirect(`/chat/${other._id}`);
  }

  await Message.create({
    from: me._id,
    to: other._id,
    content: content.trim()
  });

  res.redirect(`/chat/${other._id}`);
});

// Création d'une publication
app.post('/posts', requireLogin, async (req, res) => {
  const user = await User.findById(req.session.userId);
  const { content } = req.body;

  if (!content || !content.trim()) {
    return res.redirect('/');
  }

  await Post.create({
    author: user._id,
    content: content.trim()
  });

  res.redirect('/');
});

// Création d'un commentaire sur un post
app.post('/posts/:postId/comments', requireLogin, async (req, res) => {
  const user = await User.findById(req.session.userId);
  const { content } = req.body;
  const { postId } = req.params;

  if (!content || !content.trim()) {
    return res.redirect('/');
  }

  const post = await Post.findById(postId);
  if (!post) {
    return res.redirect('/');
  }

  await Comment.create({
    post: post._id,
    author: user._id,
    content: content.trim()
  });

  res.redirect('/');
});

// ====== LANCEMENT SERVEUR ======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`DAMIBOOK tourne sur http://localhost:${PORT}`);
});
