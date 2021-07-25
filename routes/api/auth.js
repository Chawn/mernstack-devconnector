const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const auth = require('../../middleware/auth')
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User')
// @route   GET api/auth
// @desc    Test route
// @access  Public
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch(err){
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   GET api/users
// @desc    Authenticate user & get token
// @access  Public
router.post(
  '/', 
  [
    check('email', 'คุณยังไม่ได้ใส่อีเมล').isEmail(),
    check('password', 'คุณยังไม่ได้ใส่รหัสผ่าน').exists()
  ], 
  async (req, res) => {
    const errors = validationResult(req, res);
    if(!errors.isEmpty()){
      return res.status(400).json({ errors: errors.array() })
    }

    const { email, password } = req.body;

    try {
      // See if user exists
      let user = await User.findOne({ email });

      if(!user){
        return res
          .status(400)
          .json({ errors: [{ msh: 'อีเมลนี้ไม่มีในระบบ โปรดสมัครสมาชิก'}] })
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if(!isMatch){
        return res
              .status(400)
              .json({ errors: [{ msh: 'รหัสผ่านไม่ถูกต้อง'}] })
      }

      const payload = {
        user: {
          id: user.id
        }
      }

      jwt.sign(
        payload, 
        config.get('jwtSecret'),
        { expiresIn: 360000 },
        (err, token) => {
          if(err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

module.exports = router;