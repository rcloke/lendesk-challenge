const express = require('express');
const redis = require('redis');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const e = require('express');

dotenv.config();

async function main() {

    const redisClient = redis.createClient({
        url: process.env.REDIS_URL
    }).on('error', (err) => {
        console.log('Redis client error: ', err);        
    });
    
    await redisClient.connect();

    const app = express();
   
    app.use(express.json());

    /**
     * Create a new user
     * POST /users  
     */
    app.post('/user', async (req, res) => {

        const { username, password } = req.body;

        const errors = [];

        // check for required fields
        if (!username || !password) {
            errors.push({ 
                'param': 'username', 
                'message': 'Username and password are required' 
            });
            return res.status(400).json({ errors });            
        }

        /**
         * Each condition is checked individually for code readability/maintainability 
         * AND so the user can be informed of all the requirements that are not met.
         * TODO: Move these checks to a separate function/module/file
         */

        /**
         * Ensure username is:
         * - at least 6 characters long but less then 32 characters
         * - contains only alphanumeric characters and special characters .-_@
         */
        if (username.length < 6) {
            errors.push({
                'param': 'username',
                'message': 'Username must be at least 6 characters long'
            });
        }
        if (username.length > 32) {
            errors.push({
                'param': 'username',
                'message': 'Username must be less than 32 characters long'
            });
        }
        if (!username.match(/^[a-zA-Z0-9\._\-@]+$/)) {
            errors.push({
                'param': 'username',
                'message': 'Username must contain only alphanumeric characters and special characters .-_@'
            });
        }

        /**
         * Check if user exists
         * - only check if there are no username validation errors
         * - if username exists, stop here and return error
         */
        if (errors.length == 0) {          
            const checkUser = await redisClient.get('user:'+username);            
            if (checkUser) {
                errors.push({
                    'param': 'username',
                    'message': 'Username already exists'
                });
                return res.status(409).json({ errors });                
            }            
        }
    
        /**
         * Ensure password is: 
         * - at least 8 characters long but less then 32 characters
         * - contains at least one uppercase letter
         * - one lowercase letter
         * - one number
         * - one special character.  The accepted special characters are: !@#$%^&*()_+|~-=`{}[]:";'<>?,./
         */  
        if (password.length < 8) {
            errors.push({ 
                'param': 'password',
                'message': 'Password must be at least 8 characters long'
            });    
        }
        if (password.length > 32) {
            errors.push({ 
                'param': 'password',
                'message': 'Password must be less than 32 characters long'
            });
        }
        if (!password.match(/[A-Z]/)) {
            errors.push({ 
                'param': 'password',
                'message': 'Password must contain at least one uppercase letter'
            });
        }
        if (!password.match(/[a-z]/)) {
            errors.push({ 
                'param': 'password',
                'message': 'Password must contain at least one lowercase letter'
            });
        }
        if (!password.match(/[0-9]/)) {
            errors.push({ 
                'param': 'password',
                'message': 'Password must contain at least one number'
            });
        }
        if (!password.match(/[!@#$%^&*()_+|~\-=`{}[\]:";'<>?,.\/]/)) {
            errors.push({ 
                'param': 'password',
                'message': 'Password must contain at least one special character'
            });
        }   

        /**
         * If there are any errors, return them and stop here
         */
        if (errors.length > 0) {
            return res.status(400).json({ errors });
        } 

        /**
         * CREATE USER
         */

        /**
         * Hash the password
         * TODO: determine the best salted rounds value.  Larger values take longer to hash.
         */
        const hashedPassword = bcrypt.hashSync(password, 5);

        /**
         * Store the user and hashed password in Redis
         */
        const user = await redisClient.set('user:'+username, hashedPassword);        
        if (user == 'OK') {
            /** 
             * Return success message
             * TODO: return 201 status code?
             */
            return res.status(200).json({ message: 'User created' });             
        }        

        /**
         * If we get here, something went wrong
         */ 
        errors.push({
            'param': 'username',
            'message': 'Unable to create user'
        });
        return res.status(500).json({ errors });        

    });

    /**
     * Auth user
     * POST /auth
     */
    app.post('/auth', async (req, res) => {

        const { username, password } = req.body;

        // check for required fields
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        /**
         * Check if user exists and get hashed password
         * TODO: return 404 status code if not found?
         */
        const hashedPassword = await redisClient.get('user:'+username);        
        if (hashedPassword) {
            /**
             * Check if password is correct
             */
            if (bcrypt.compareSync(password, hashedPassword)) {                
                /**
                 * Return success message
                 * TODO: return JWT?
                 */
                return res.status(200).json({ message: 'User authenticated' });
            }
        } 

        return res.status(401).json({ error: 'Invalid username or password' });            

    });

    app.listen(3000, () => {
        console.log('Authentication API listening on port 3000');
    });

}

main().catch(err => {
    console.error(err);
});