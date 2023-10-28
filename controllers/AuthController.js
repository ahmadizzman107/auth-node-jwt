const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../model/user');

// Temp storage
let refreshTokens = [];
// Method
const sign = (_id, email) =>
  jwt.sign({ user_id: _id, email }, process.env.TOKEN_KEY, {
    expiresIn: process.env.EXPIRES_IN,
  });

const register = async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    if (!(email && password && firstName && lastName)) {
      res.status(400).send('All input is required');
    }

    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(409).send('User Already Exist. Please Login');
    }

    encryptedUserPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      first_name: firstName,
      last_name: lastName,
      email: email.toLowerCase(),
      password: encryptedUserPassword,
    });

    const token = sign(user._id, email);
    user.token = token;

    res.status(201).json(user);
  } catch (err) {
    console.error(err);
    res.status(500);
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!(email && password)) {
      res.status(400).send('All input is required');
    }
    const user = await User.findOne({ email });

    if (user && bcrypt.compare(password, user.password)) {
      const token = sign(user._id, email);
      const refresh = jwt.sign(
        { user_id: user._id, email },
        process.env.REFRESH_KEY
      );
      refreshTokens.push(refresh);

      user.token = token;
      user.save();

      res.cookie('access_token', token, {
        maxAge: 36000000,
        httpOnly: true,
      });
      return res
        .status(200)
        .json({ token, refresh, expiresIn: process.env.EXPIRES_IN });
    }
    return res.status(400).send('Invalid Credentials');
  } catch (err) {
    console.error(err);
    res.status(500);
  }
};

const refresh = (req, res) => {
  const refreshToken = req.body.token;

  if (!refreshToken) return res.status(401);
  if (!refreshTokens.includes(refreshToken)) return res.status(403);

  jwt.verify(refreshToken, process.env.REFRESH_KEY, async (error, user) => {
    if (error) return res.status(403);

    const accessToken = sign(user._id, user.email);

    const currentUser = await User.findOne({ email: user.email });
    currentUser.token = accessToken;
    currentUser.save();

    res.status(201).json({ accessToken });
  });
};

const logout = (req, res) => {
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.status(204);
};

const currentAuth = async (req, res) => {
  try {
    const currentUser = await User.findOne({
      email: req.user.email,
    });

    if (!currentUser) return res.status(404).send('User not found!');

    const userProfile = {
      firstName: currentUser.first_name,
      lastName: currentUser.last_name,
      email: currentUser.email,
    };
    return res.status(201).json(userProfile);
  } catch (error) {
    console.error(err);
    res.status(500);
  }
};
module.exports = {
  register,
  login,
  currentAuth,
  refresh,
  logout,
};
