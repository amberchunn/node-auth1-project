const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const session = require('express-session')
const SessionStore = require('connect-session-knex')(session)
const usersRouter = require('./users/users-router')
const authRouter = require('./users/users-router')
const db = require('../data/db-config')

/**
  Do what needs to be done to support sessions with the `express-session` package!
  To respect users' privacy, do NOT send them a cookie unless they log in.
  This is achieved by setting 'saveUninitialized' to false, and by not
  changing the `req.session` object unless the user authenticates.

  Users that do authenticate should have a session persisted on the server,
  and a cookie set on the client. The name of the cookie should be "chocolatechip".

  The session can be persisted in memory (would not be adecuate for production)
  or you can use a session store like `connect-session-knex`.
 */

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session({
  resave: false,
  saveUninitialized: false,
  name: 'chocolatechip',
  secret: 'mochi',
  store: new SessionStore({
    knex: db,
    createtable: true,
  }),
}))

server.use(authRouter)
server.use(usersRouter)

server.get("/", (req, res) => {
  res.json({ api: "API Status: Active" });
});

server.use((err, req, res, next) => { // eslint-disable-line
  res.status(500).json({
    message: err.message,
    stack: err.stack,
  });
});

module.exports = server;
