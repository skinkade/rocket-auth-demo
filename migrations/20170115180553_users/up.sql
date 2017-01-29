CREATE TABLE users (
    username    TEXT PRIMARY KEY,
    pw_hash     TEXT NOT NULL,
    user_roles  TEXT[] NOT NULL DEFAULT '{"user"}',
    auth_token  TEXT
);

-- Passwords same as usernames
INSERT INTO users
VALUES (
    'wizard',
    '$argon2i$m=4096,t=3,p=1$r/AB1gKgFXdW2VB7PB6IJQ$f82eK85vMatKObM91wObV5kKDCSOP/AJSrcR4SLEmNQ',
    '{"admin", "developer"}',
    'JNWNRRNXGSH7XHP2D76SYSECK4'
);
INSERT INTO users
VALUES (
    'd4b0ss',
    '$argon2i$m=4096,t=3,p=1$hbkIMra3TSP4UwPdr5015g$wwHFUFL7JCBRoizkzEhsjAGtDlx5WVZeYZEieegkjqw',
    '{"c-level", "finance"}'
);
