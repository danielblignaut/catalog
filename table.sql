DROP DATABASE IF EXISTS catalog;
CREATE DATABASE catalog;

\connect catalog

CREATE TABLE users (
	ID SERIAL PRIMARY KEY,
	name varchar(255),
	email varchar(255),
	picture varchar(255)
);

CREATE TABLE categories (
	ID SERIAL PRIMARY KEY,
	name varchar(255),
	user_id SERIAL
);
CREATE TABLE items (
	ID SERIAL PRIMARY KEY,
	name varchar(255),
	description varchar(255),
	category_id SERIAL,
	user_id SERIAL,
	picture varchar(255),
	updated date,
	created date
);