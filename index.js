const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const serviceAccount = require('./seviceaccountkey2');
const bcrypt = require('bcrypt');
const session = require('express-session'); 

const crypto = require('crypto');

const secretKey = crypto.randomBytes(32).toString('hex');


app.use(session({
  secret: 'secretkey', 
  resave: false,
  saveUninitialized: true
}));


app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: false }));

app.get('/', function (req, res) {
  res.render('home');
});

app.get('/signup', function (req, res) {
  res.render('signup');
});

app.post('/signupsubmit', async (req, res) => {
  const { Entername, Enteremail, Password } = req.body;

  if (!Entername) {
    return res.send("Entername is missing or empty");
  }

  try {
    const hashedPassword = await bcrypt.hash(Password, 10);
    const userSnapshot = await db.collection("users").where('email', '==', Enteremail).get();

    if (userSnapshot.size === 0) {
      await db.collection("users").add({
        userName: Entername,
        email: Enteremail,
        password: hashedPassword,
      });
      res.render("login");
    } else {
      return res.send("This email already exists");
    }
  } catch (error) {
    console.error("Error during sign-up:", error);
    res.status(500).send("Internal server error");
  }
});

app.get('/login', function (req, res) {
  res.render('login');
});

app.post('/loginsubmit', async (req, res) => {
  const { Enteremail, Password } = req.body;

  try {
    // Check if Enteremail or Password is undefined or empty
    if (!Enteremail || !Password) {
      return res.send("Email and password are required.");
    }

    // Find the user by email
    const userSnapshot = await db.collection("users").where('email', '==', Enteremail).get();

    if (userSnapshot.empty) {
      return res.send("User not found");
    }

    const userData = userSnapshot.docs[0].data();
    const isPasswordValid = await bcrypt.compare(Password, userData.password);

    if (isPasswordValid) {
      // Start a session
      req.session.user = userData;

      res.redirect("/dashboard");
    } else {
      res.send("Please enter valid details");
    }
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).send("Internal server error");
  }
});

app.get('/dashboard', async (req, res) => {
  if (req.session.user) {
    res.render('dashboard', { user: req.session.user });
  } else {
    res.redirect("/login");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log(`Example app listening on port ${PORT}!`);
});
