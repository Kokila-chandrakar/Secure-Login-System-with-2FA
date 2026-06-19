// server.js - Main backend server (Express + SQLite)
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const session = require('express-session');
const path = require('path');

const app = express();
const port = 3000;
