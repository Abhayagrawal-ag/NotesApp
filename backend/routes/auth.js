import express from 'express';
import User from '../models/User.js';
import bcrypt from 'bcrypt';
import Note from '../models/Note.js';
import validator from 'validator';
import {SendVerificationCode} from '../middleware/Email.js'
const router = express.Router();
// Register route
router.post('/register', async (req, res) => {
  try{
  const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    if (!validator.isEmail(email)) {
      return res.status(400).json({
        message: 'Invalid email format' });
    }
    const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ 
          message: 'User already exists and is verified. Please login.' 
        });
      }
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString()
    const user = new User({
      email,
      password: hashedPassword,
      verificationCode,
      isVerified:false
    });
    await user.save();
    SendVerificationCode(user.email, verificationCode);
    res.status(201).json({message: 'User registered successfully' });
  }catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({message: 'Internal server error' });
  }
});

// Login route
router.post('/login', async (req, res) => {
  try{
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({message: 'Email and password are required' });
  }
  if (!validator.isEmail(email)) {
    return res.status(400).json({message: 'Invalid email format' });
  }
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: 'Invalid email' });
  }
  if (!user.isVerified) {
  return res.status(400).json({ 
    message: 'Please verify your email before logging in. Check your email for verification code.' 
  });
}

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({message: 'Invalid password' });
  }
  res.status(200).json({ message: 'Login successful' 
     });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

//delete route
router.delete('/delete', async (req, res) => {
  const { email,password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }
  try {
    const user = await User.findOne({email});
    if(!user){
      return res.status(404).json({ message: 'User not found' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({message: 'Invalid password' });
    }
    await User.deleteOne({email})
    await Note.deleteMany({userEmail: email});
    res.status(200).json({ message: 'User and associated notes deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// verify
router.post('/verify', async (req, res) => {
  try {
    const { code } = req.body;
    console.log('Verification attempt with code:', code);
    if (!code) {
      return res.status(400).json({ 
        message: "Verification code is required" 
      });
    }
    const user = await User.findOne({
      verificationCode: code,
    });
    console.log('User found:', user ? 'Yes' : 'No');
    if (!user) {
      return res.status(400).json({  
        message: "Invalid or expired verification code" 
      });
    }
    await User.findOneAndUpdate(
      { _id: user._id },
      { 
        $set: { isVerified: true },
        $unset: { verificationCode: 1 }
      }
    );
    console.log('User verified successfully:', user.email);
    res.status(200).json({ 
      message: "Email verified successfully! You can now log in." 
    }); 
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({  
      message: "Internal server error" 
    });
  }
})
export default router;


  



  
