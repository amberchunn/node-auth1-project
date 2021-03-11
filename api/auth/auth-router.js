// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!

const express = require('express')
const bcrypt = require('bcryptjs')
const { checkUsernameFree, checkPasswordLength, checkUsernameExists } = require('./auth-middleware')
const Users = require('../users/users-model')


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

router.post('/api/auth/register', checkUsernameFree(), checkPasswordLength(), async (req, res, next) => {
  try {
    const { username, password } = req.body
    const user = await Users.findBy( { username } ).first()

    if ( user ) {
      return res.status(422).json({
        message: 'username taken',
      })
    }

    const newUser = await Users.add({
      username,
      password: await bcrypt.hash(password, 4),
    })

    res.status(201).json(newUser)

  } catch (err) {
    next(err)
  }
})

router.post('/api/auth/login', checkUsernameExists(), async (req, res, next) => {
  try {
    const { username, password } = req.body

    const user = await Users.findBy( { username } ).first()

    const validPass = await bcrypt.compare(password, user ? user.password : '')

    if (!user || !validPass) {
      return res.status(401).json({ message: 'invalid credentials' })
    }

    req.session.chocolatechip = user
    res.json({ message: `welcome ${user.username}`});
  } catch (err) {
    next(err)
  }
})

router.get('/api/auth/logout', async (req, res, next) => {
  try {
    if (!req.session || !req.session.chocolatechip) {
      res.status(200).json({ message: 'no session' })
    } else {
      req.session.destroy((err) => {
        if (err) {
          next(err)
        } else {
          res.status(200).json({message: 'logged out'})
        }
      })
    }
  } catch (err) {
    next(err)
  }
})

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */


// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router
