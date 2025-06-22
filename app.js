const { Pool } = require("pg");
const express = require("express");

// This enables EJS as the view engine, and that our app should look for templates in the /views subdirectory.
const path = require("node:path");

// Loads the session middleware.
// It allows Express to store session data between requests — needed to keep users logged in.
// To make sure our user is logged in, and to allow them to stay logged in as they move around our app,
// passport internally calls a function from express-session that uses some data to create a cookie
// called connect.sid which is stored in the user’s browser.
// We are not using session directly, it's a dependecy that is used in the background by passport.js
const session = require("express-session");

// Loads Passport.js, a flexible authentication library.
// Used to manage login sessions and authentication strategies (like local, OAuth, etc.).
const passport = require("passport");

// Loads the Local Strategy from Passport.
// This lets users log in with a username and password (as opposed to Google, GitHub, etc.).
const LocalStrategy = require("passport-local").Strategy;

require("dotenv").config();

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// This function acts a bit like a middleware
// You don’t call this function yourself, Passport calls it automatically during authentication.
// Passport passes in the username and password from the login form.
// It expects you to call done() when you’re done verifying the user.
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
      );
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      if (user.password !== password) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// These next two functions define what bit of information passport is looking for
// when it creates and then decodes the cookie.
// The reason they require us to define these functions is so that
// we can make sure that whatever bit of data it’s looking for actually exists in our Database! 
// we aren’t going to be calling these functions on our own and we just need to define them, 
// they’re used in the background by passport.

// (1) passport.serializeUser takes a callback which contains the information we wish to store in the session data.
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// (2) passport.deserializeUser is called when retrieving a session,
// where it will extract the data we “serialized” in it then ultimately
// attach something to the .user property of the request object (req.user)
// for use in the rest of the request.
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
});

const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());

// Middleware to parse URL-encoded data from HTML form submit
app.use(express.urlencoded({ extended: false }));

app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.get("/", (req, res) => res.render("index"));

app.post("/sign-up", async (req, res, next) => {
  try {
    await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
      req.body.username,
      req.body.password,
    ]);
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

app.listen(3000, () => console.log("app listening on port 3000"));
