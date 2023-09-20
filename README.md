# LendDesk Coding Challenge

## Validation
- Implements custom validation checks rather than relying on 3rd party modules

## Security
- Assumes rate limiting, bot detection, etc to be implemented in infrastructure layer, otherwise would implement using middleware express-rate-limit, helmet, etc
- 2FA/MFA solution recommended in production when sensitive data is processed/accessed
- Passwords stored as salted hashes
- Use HTTPS in production

## Data Storage
- Username changes handled by renaming Redis key with RENAME command
- Could be implemented with HSET/hashes for each user, but opted for simple key/value pairs for simplicity