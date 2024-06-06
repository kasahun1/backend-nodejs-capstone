const express = require('express');
const router = express.Router();
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const logger = require('../logger');
const connectToDatabase = require('../models/db');

const JWT_SECRET = process.env.JWT_SECRET || 'setasecret';

router.post('/register', async (req, res) => {
    try {
        // Task 1: Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
        const db = await connectToDatabase();
        // Task 2: Access MongoDB `users` collection
        const collection = db.collection("users");
        if (!req.body.email || !req.body.password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        // Task 3: Check if user credentials already exists in the database and throw an error if they do 
        const existingEmail = await collection.findOne({ email: req.body.email });

        if (existingEmail) {
            logger.error('Email id already exists');
            return res.status(400).json({ error: 'Email id already exists' });
        }
        // Task 4: Create a hash to encrypt the password so that it is not readable in the database
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        // Task 5: Insert the user into the database
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });
        const result = await collection.insertOne(newUser);
        // Task 6: Create JWT authentication if passwords match with user._id as payload
        const payload = {
            user: {
                id: result.insertedId,
            },
        };
        
        const authtoken = jwt.sign(payload, JWT_SECRET);
        // Task 7: Log the successful registration using the logger
        logger.info('User registered successfully');
        // Task 8: Return the user email and the token as a JSON
        res.json({ authtoken, email });
    } catch (e) {
         return res.status(500).send('Internal server error');
    }
});

router.post('/login', async (req, res) => {
    try {
        // Task 1: Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
        const db = await connectToDatabase();
        // Task 2: Access MongoDB `users` collection
        const collection = db.collection("users");
        if (!req.body.email || !req.body.password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        // Task 3: Check for user credentials in database
        const theUser = await collection.findOne({ email: req.body.email });
        if (!theUser) {
            return res.status(404).json({ message: 'User not found' });
        }
        // Task 4: Check if the password matches the encrypted password and send appropriate message on mismatch
        if (theUser) {
            let result = await bcryptjs.compare(req.body.password, theUser.password)
          if(!result) {
                logger.error('Passwords do not match');
                return res.status(404).json({ error: 'Wrong pasword' });
            }
            //continue other tasks
        }
        // Task 5: Fetch user details from a database
        const userName = theUser.firstName;
        const userEmail = theUser.email;
        // Task 6: Create JWT authentication if passwords match with user._id as payload
        let payload = {
            user: {
                id: theUser._id.toString(),
             },
         };
         const authtoken = jwt.sign(payload, JWT_SECRET)

        res.json({authtoken, userName, userEmail });
        // Task 7: Send appropriate message if the user is not found
        logger.info(`User logged in with email: ${userEmail}`);

    } catch (e) {
         return res.status(500).send('Internal server error');
    }
});

module.exports = router;