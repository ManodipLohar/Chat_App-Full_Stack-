const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const Message = require('./models/Message');
const ws = require('ws');
const fs = require('fs');

dotenv.config();

const app = express();
const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);

// MongoDB connection with async/await
async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGO_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error.message);
    process.exit(1); // Exit the app if the DB connection fails
  }
}
connectDB();

app.use('/uploads', express.static(__dirname + '/uploads'));
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  credentials: true,
  origin: process.env.CLIENT_URL,
}));

async function getUserDataFromRequest(req) {
  return new Promise((resolve, reject) => {
    const token = req.cookies?.token;
    if (token) {
      jwt.verify(token, jwtSecret, {}, (err, userData) => {
        if (err) return reject(err);
        resolve(userData);
      });
    } else {
      reject('No token');
    }
  });
}

app.get('/test', (req, res) => {
  res.json('test ok');
});

app.get('/messages/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const userData = await getUserDataFromRequest(req);
    const ourUserId = userData.userId;
    const messages = await Message.find({
      sender: { $in: [userId, ourUserId] },
      recipient: { $in: [userId, ourUserId] },
    }).sort({ createdAt: 1 });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.get('/people', async (req, res) => {
  const users = await User.find({}, { '_id': 1, username: 1 });
  res.json(users);
});

app.get('/profile', (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    jwt.verify(token, jwtSecret, {}, (err, userData) => {
      if (err) return res.status(403).json({ error: 'Invalid token' });
      res.json(userData);
    });
  } else {
    res.status(401).json({ error: 'No token provided' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const foundUser = await User.findOne({ username });
  if (foundUser) {
    const passOk = bcrypt.compareSync(password, foundUser.password);
    if (passOk) {
      jwt.sign({ userId: foundUser._id, username }, jwtSecret, {}, (err, token) => {
        if (err) return res.status(500).json({ error: 'Failed to generate token' });
        res.cookie('token', token, { sameSite: 'none', secure: true }).json({
          id: foundUser._id,
        });
      });
    } else {
      res.status(401).json({ error: 'Incorrect password' });
    }
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

app.post('/logout', (req, res) => {
  res.cookie('token', '', { sameSite: 'none', secure: true }).json('ok');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
    const createdUser = await User.create({
      username,
      password: hashedPassword,
    });
    jwt.sign({ userId: createdUser._id, username }, jwtSecret, {}, (err, token) => {
      if (err) throw err;
      res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
        id: createdUser._id,
      });
    });
  } catch (err) {
    res.status(500).json({ error: 'User registration failed' });
  }
});

const server = app.listen(4040, () => {
  console.log('Server running on port 4040');
});

// WebSocket setup
const wss = new ws.WebSocketServer({ server });
wss.on('connection', (connection, req) => {
  function notifyAboutOnlinePeople() {
    [...wss.clients].forEach(client => {
      client.send(JSON.stringify({
        online: [...wss.clients].map(c => ({ userId: c.userId, username: c.username })),
      }));
    });
  }

  connection.isAlive = true;
  connection.timer = setInterval(() => {
    connection.ping();
    connection.deathTimer = setTimeout(() => {
      connection.isAlive = false;
      clearInterval(connection.timer);
      connection.terminate();
      notifyAboutOnlinePeople();
    }, 1000);
  }, 5000);

  connection.on('pong', () => {
    clearTimeout(connection.deathTimer);
  });

  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenCookieString = cookies.split(';').find(str => str.startsWith('token='));
    if (tokenCookieString) {
      const token = tokenCookieString.split('=')[1];
      jwt.verify(token, jwtSecret, {}, (err, userData) => {
        if (!err) {
          const { userId, username } = userData;
          connection.userId = userId;
          connection.username = username;
        }
      });
    }
  }

  connection.on('message', async (message) => {
    const messageData = JSON.parse(message.toString());
    const { recipient, text, file } = messageData;
    let filename = null;
    if (file) {
      const parts = file.name.split('.');
      const ext = parts[parts.length - 1];
      filename = Date.now() + '.' + ext;
      const path = __dirname + '/uploads/' + filename;
      const bufferData = Buffer.from(file.data.split(',')[1], 'base64');
      fs.writeFile(path, bufferData, () => {
        console.log('File saved:', path);
      });
    }
    if (recipient && (text || file)) {
      const messageDoc = await Message.create({
        sender: connection.userId,
        recipient,
        text,
        file: file ? filename : null,
      });
      [...wss.clients]
        .filter(c => c.userId === recipient)
        .forEach(c => c.send(JSON.stringify({
          text,
          sender: connection.userId,
          recipient,
          file: file ? filename : null,
          _id: messageDoc._id,
        })));
    }
  });

  notifyAboutOnlinePeople();
});
