require('dotenv').config();
require('./config/database').connect();
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// local imports
const verify = require('./middleware/auth');
const {
  register,
  login,
  currentAuth,
  refresh,
  logout,
} = require('./controllers/AuthController');

app.get('/', () => {
  console.log('Goin live!');
});
app.post('/register', register);
app.post('/login', login);
app.post('/refresh', refresh);
app.delete('/logout', logout);
app.get('/me', verify, currentAuth);

module.exports = app;
