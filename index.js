require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const sqlite3 = require('sqlite3').verbose();

// Add body-parser middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors());
const port = process.env.PORT || 8000;

// Create SQLite database connection
const db = new sqlite3.Database('./books.db'); // Replace with your desired database file name or path

const JWT_SECRET = 'secret';

// Create 'users' table
db.serialize(() => {
  db.run(
    'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT, password TEXT)'
  );
  db.run(
    'CREATE TABLE IF NOT EXISTS books (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, author TEXT, price REAL, image TEXT, user_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)'
  );
});

// List all books
app.get('/books', (req, res) => {
  const query = 'SELECT * FROM books ORDER BY id DESC';
  db.all(query, (error, rows) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    res.json(rows);
  });
});

// Add a new book
app.post('/books', authenticateToken, (req, res) => {
  // Ensure user is logged in before adding a book
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { title, author, price, image } = req.body;
  const userId = req.user.id;
  const query =
    'INSERT INTO books (title, author, price, image, user_id) VALUES (?, ?, ?, ?, ?)';
  db.run(query, [title, author, price, image, userId], function (error) {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    const id = this.lastID;
    res.json({ id, title, author, price, image });
  });
});

// Update a book
app.put('/books/:id', authenticateToken, (req, res) => {
  // Ensure user is logged in before updating a book
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;
  const { title, author, price, image } = req.body;
  const query =
    'UPDATE books SET title = ?, author = ?, price = ?, image = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?';
  const userId = req.user.id;
  db.run(
    query,
    [title, author, price, image, id, userId],
    function (error) {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'An error occurred' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Book not found or unauthorized' });
      }
      res.json({ id, title, author, price, image });
    }
  );
});

// Delete a book
app.delete('/books/:id', authenticateToken, (req, res) => {
  // Ensure user is logged in before deleting a book
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;
  const query = 'DELETE FROM books WHERE id = ? AND user_id = ?';
  const userId = req.user.id;
  db.run(query, [id, userId], function (error) {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Book not found or unauthorized' });
    }
    res.json({ message: 'Book deleted successfully' });
  });
});

// Get the current logged-in user information
app.get('/user', authenticateToken, (req, res) => {
  // Ensure user is logged in before retrieving user information
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const userId = req.user.id;
  const query = 'SELECT id, name, email FROM users WHERE id = ?';
  db.get(query, [userId], (error, row) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    if (!row) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(row);
  });
});

// Register a new user
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Check if user with the same email already exists
  const checkQuery = 'SELECT * FROM users WHERE email = ?';
  db.get(checkQuery, [email], async (error, row) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    if (row) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    const insertQuery = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    db.run(insertQuery, [name, email, hashedPassword], function (error) {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'An error occurred' });
      }
      const userId = this.lastID;

      // Create and return JWT token
      const token = jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '1d' });
      res.json({ token });
    });
  });
});

// Login and get JWT token
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Find the user by email
  const query = 'SELECT * FROM users WHERE email = ?';
  db.get(query, [email], async (error, row) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    if (!row) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if the password matches
    const passwordMatches = await bcrypt.compare(password, row.password);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Create and return JWT token
    const token = jwt.sign({ id: row.id }, JWT_SECRET, { expiresIn: '1d' });

    // get the user details
    const userQuery = 'SELECT * FROM users WHERE id = ?';
    db.get(userQuery, [row.id], async (error, user) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'An error occurred' });
      }
      res.json({ user, token });
    });
  });
});

// Middleware to authenticate the token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) {
    return res.status(401).json({ error: 'Authentication token required' });
  }

  jwt.verify(token, JWT_SECRET, (error, user) => {
    if (error) {
      console.error(error);
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Start the server
app.listen(port, () => {
  console.log(`Book store app listening at http://localhost:${port}`);
});

