-- OPTIONAL DESTRUCTIVE RESET - DO NOT RUN UNTIL YOUR BACKUP IS VERIFIED.
-- FRESH_DATABASE.sql is the safe default and does not drop data.
DROP DATABASE IF EXISTS smarthostel_management;
CREATE DATABASE smarthostel_management CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE smarthostel_management;
-- After this point, run FRESH_DATABASE.sql from the project to create all tables.
