// Require the `restricted` middleware from `auth-middleware.js`. You will need it here!
const express = require('express')
const bcrypt = require('bcryptjs')
const { restricted, checkPasswordLength, checkUsernameExists, checkUsernameFree } = require('../auth/auth-middleware')
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

router.post('/api/auth/register', checkPasswordLength(), async (req, res, next) => {
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

// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router
