// Require the `restricted` middleware from `auth-middleware.js`. You will need it here!
const express = require('express')
const { restricted } = require('../auth/auth-middleware')
const Users = require('./users-model')


const router = express.Router()

/**
  [GET] /api/users

  This endpoint is RESTRICTED: only authenticated clients
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "bob"
    },
    // etc
  ]

  response on non-authenticated:
  status 401
  {
    "message": "You shall not pass!"
  }
 */

router.get('/api/users', restricted(), async (req, res, next) => {
  try {
    const user = await Users.find()
    if (!user) {
      res.status(401).json({message: 'You shall not pass!'})
    } else {
      res.status(200).json(user);
    }
  } catch (err) {
    next(err)
  }
})

// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router
