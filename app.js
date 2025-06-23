const { Pool } = require("pg");
const express = require("express");

// Import bcrypt library for password hashing
const bcrypt = require("bcrypt");

// This enables EJS as the view engine, and that our app should look for
// templates in the /views subdirectory.
const path = require("node:path");

// Loads the session middleware.
// It allows Express to store session data between requests — needed to keep
// users logged in.
// To make sure our user is logged in, and to allow them to stay logged in
// as they move around our app, passport internally calls a function from
// express-session that uses some data to create a cookie called connect.sid
// which is stored in the user’s browser.
// We are not using session directly, it's a dependecy that is used in the
// background by passport.js
const session = require("express-session");

// Loads Passport.js, a flexible authentication library.
// Used to manage login sessions and authentication strategies (like local,
// OAuth, etc.).
const passport = require("passport");

// Loads the Local Strategy from Passport.
// This lets users log in with a username and password (as opposed to Google,
// GitHub, etc.).
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
// You don’t call this function yourself, Passport calls it automatically
// during authentication.
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

      //   * Without Using Bcrypt
      //   if (user.password !== password) {
      //     return done(null, false, { message: "Incorrect password" });
      //   }

      //  * Using Bcrypt
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // passwords do not match!
        return done(null, false, { message: "Incorrect password" });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// These next two functions define what bit of information passport is
// looking for when it creates and then decodes the cookie.
// The reason they require us to define these functions is so that
// we can make sure that whatever bit of data it’s looking for actually
// exists in our Database!
// we aren’t going to be calling these functions on our own and we just
// need to define them, they’re used in the background by passport.

// (1) passport.serializeUser takes a callback which contains the
// information we wish to store in the session data.
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

// Set up session management with express-session:
//
// - secret: a key used to sign and verify the session ID cookie,
//   preventing tampering. Use a strong, random value stored securely.
//
// - resave: when true, forces the session to be saved back to the store
//   on every request, even if it hasn't changed. This can help update the
//   session’s "last accessed" time in some stores to prevent premature
//   expiration.
//   Set to false to save only when the session data changes (better for
//   performance), but some stores may require true to keep sessions alive
//   correctly and track user engagement or session duration.
//
// - saveUninitialized: when true, saves new sessions to the store even if
//   they have no data (e.g., guest users who don't log in). Setting false
//   avoids storing empty sessions and reduces storage usage.
//
// Typical usage:
//   - Keep `secret` secure and consistent across server restarts to avoid
//     invalidating sessions.
//   - Set `resave` based on your session store’s needs (false for most
//     cases).
//   - Set `saveUninitialized` to false to avoid saving empty sessions.
app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());

// Middleware to parse URL-encoded data from HTML form submit
app.use(express.urlencoded({ extended: false }));

app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.get("/", (req, res) => res.render("index", { user: req.user }));

// Handles user sign-up:
// - Hash the user's plaintext password securely using bcrypt with a salt
//   rounds of 10.
//   Salting a password means adding extra random characters to it,
//   the password plus the extra random characters are then fed into the
//   hashing function.
//   Salting is used to make a password hash output unique, even for users
//   who use the same password, and to protect against rainbow tables and
//   dictionary attacks.
//   This ensures passwords are stored safely and not in plaintext,
//   protecting against data breaches.
// - Insert the username and hashed password into the users table in the
//   database using parameterized queries to prevent SQL injection attacks.
// - Redirect the user to the homepage after successful registration.
// - If an error occurs (e.g., database issue), log it and pass it to the
//   error handler middleware.
app.post("/sign-up", async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await pool.query("insert into users (username, password) values ($1, $2)", [
      req.body.username,
      hashedPassword,
    ]);
    res.redirect("/");
  } catch (error) {
    console.error(error);
    next(error);
  }
});

// This makes sure that log out link actually work for us.
// As you can see it’s sending us to /log-out so all we need to do is add
// a route for that in our app.js. Conveniently, the passport middleware
// adds a logout function to the req object, so logging out is as easy as this:
app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// When we call pasport.authenticate(), this middleware performs numerous
// functions.
// One of which is looking at the request body for parameters named
// 'username' and 'password'.
// Then it runs LocalStrategy that we defined earlier to see if 'username'
// and 'password' are in the database. It then creates a session cookie that
// gets stored in the user’s browser and used in all future requests to see
// whether or not that user is logged in.
// It can also redirect you to different routes based on whether the login
// is a success or a failure.
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

app.listen(3000, () => console.log("app listening on port 3000"));
