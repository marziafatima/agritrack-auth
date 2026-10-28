-- AgriTrack: Users table (Sign In / Sign Up module)
-- The Flask app creates this table automatically; this file is for documentation / viva.
CREATE TABLE users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(40)  NOT NULL,
  username      VARCHAR(20)  NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,              -- hashed, never plain text
  role          ENUM('Farmer','Buyer','Supplier','Admin') NOT NULL,
  phone         VARCHAR(15)  NOT NULL,
  location      VARCHAR(30)  NOT NULL,
  status        ENUM('Pending','Active','Blocked') NOT NULL DEFAULT 'Pending',
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);
