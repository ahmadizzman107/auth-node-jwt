const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../model/user');

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

    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: '5h',
      }
    );
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

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: '5h',
        }
      );

      user.token = token;
      user.save();

      res.cookie('access_token', token, {
        maxAge: 36000000,
        httpOnly: true,
      });
      return res.status(200).json({ token, expiresIn: '1h' });
    }
    return res.status(400).send('Invalid Credentials');
  } catch (err) {
    console.error(err);
    res.status(500);
  }
};

const currentAuth = async (req, res) => {
  try {
    const token =
      req.body.token || req.query.token || req.headers['x-access-token'];

    const currentUser = await User.findOne({
      token,
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
};
