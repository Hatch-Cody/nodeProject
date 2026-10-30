
"use strict";

const { Pool } = require("pg");
const argon2 = require("argon2");

// Require database credentials from environment variables.
if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL environment variable is required");
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    max: 10
});

// Argon2id password hashing configuration.
const hashOptions = {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
};

// Used to reduce timing differences for nonexistent users.
const dummyHashPromise = argon2.hash(
    "dummy-password-for-verification",
    hashOptions
);

function authenticationError() {
    const error = new Error("Invalid username or password");
    error.code = "AUTH_FAILED";
    return error;
}

/**
 * Authenticate an existing user.
 *
 * @param {string} name - Username
 * @param {string} pass - Plaintext password provided at login
 * @param {function} callback - callback(error, user)
 */
async function handleLogin(name, pass, callback) {
    if (typeof callback !== "function") {
        throw new TypeError("Callback must be a function");
    }

    // Validate input before querying the database.
    if (
        typeof name !== "string" ||
        name.length < 1 ||
        name.length > 50 ||
        typeof pass !== "string" ||
        pass.length === 0 ||
        Buffer.byteLength(pass, "utf8") > 1024
    ) {
        return callback(authenticationError(), null);
    }

    try {
        const sql = `
            SELECT id, username, email, password_hash
            FROM users
            WHERE username = $1
            LIMIT 1
        `;

        const result = await pool.query(sql, [name]);

        // User does not exist.
        if (result.rows.length === 0) {
            const dummyHash = await dummyHashPromise;
            await argon2.verify(dummyHash, pass);

            return callback(authenticationError(), null);
        }

        const user = result.rows[0];

        // Verify the supplied password against the stored hash.
        const passwordMatches = await argon2.verify(
            user.password_hash,
            pass
        );

        if (!passwordMatches) {
            return callback(authenticationError(), null);
        }

        // Authentication successful.
        // Never expose password hashes.
        return callback(null, {
            id: user.id,
            username: user.username,
            email: user.email
        });

    } catch (err) {
        console.error("Login database error:", {
            code: err.code || "UNKNOWN"
        });

        const error = new Error(
            "Authentication service unavailable"
        );
        error.code = "AUTH_SERVICE_ERROR";

        return callback(error, null);
    }
}

/**
 * Register a new user.
 *
 * @param {Array} params - [username, password, email]
 * @param {function} callback - callback(error, user)
 */
async function registerUser(params, callback) {
    if (typeof callback !== "function") {
        throw new TypeError("Callback must be a function");
    }

    if (!Array.isArray(params) || params.length !== 3) {
        return callback(
            new Error("Invalid registration parameters"),
            null
        );
    }

    const [username, password, email] = params;

    // Validate username.
    if (
        typeof username !== "string" ||
        username.length < 3 ||
        username.length > 50 ||
        !/^[a-zA-Z0-9_-]+$/.test(username)
    ) {
        return callback(
            new Error("Invalid username"),
            null
        );
    }

    // Validate password.
    if (
        typeof password !== "string" ||
        Buffer.byteLength(password, "utf8") < 12 ||
        Buffer.byteLength(password, "utf8") > 1024
    ) {
        return callback(
            new Error("Password must be at least 12 characters"),
            null
        );
    }

    // Validate email.
    if (
        typeof email !== "string" ||
        email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
        return callback(
            new Error("Invalid email address"),
            null
        );
    }

    try {
        // Securely hash the password before storing it.
        const passwordHash = await argon2.hash(
            password,
            hashOptions
        );

        const sql = `
            INSERT INTO users (
                username,
                password_hash,
                email
            )
            VALUES ($1, $2, $3)
            RETURNING id, username, email
        `;

        const result = await pool.query(sql, [
            username,
            passwordHash,
            email
        ]);

        // Registration successful.
        return callback(null, result.rows[0]);

    } catch (err) {
        // PostgreSQL unique constraint violation.
        if (err.code === "23505") {
            const error = new Error(
                "Username or email already exists"
            );
            error.code = "USER_EXISTS";

            return callback(error, null);
        }

        console.error("Registration database error:", {
            code: err.code || "UNKNOWN"
        });

        const error = new Error(
            "Registration service unavailable"
        );
        error.code = "REGISTRATION_ERROR";

        return callback(error, null);
    }
}

module.exports = {
    handleLogin,
    registerUser
};
