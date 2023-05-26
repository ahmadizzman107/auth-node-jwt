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
} = require('./controllers/AuthController');

app.post('/register', register);
app.post('/login', login);
app.get('/me', verify, currentAuth);

module.exports = app;
