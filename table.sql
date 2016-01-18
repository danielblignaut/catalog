DROP DATABASE IF EXISTS catalog;
CREATE DATABASE catalog;

\connect catalog

CREATE TABLE categories (
	ID SERIAL PRIMARY KEY,
	name varchar(255)
);
CREATE TABLE items (
	ID SERIAL PRIMARY KEY,
	name varchar(255),
	description varchar(255),
	category_id SERIAL
);