// Example of clean, safe JavaScript code.
// This file shows patterns that AI Code Sanitizer should NOT flag.
'use strict';

const express = require('express');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');

const app = express();
app.use(helmet());

const JWT_SECRET = process.env.JWT_SECRET_KEY;

function renderName(el, name) {
  // textContent escapes automatically
  el.textContent = name;
}

function issueToken(userId) {
  // exp is set explicitly
  return jwt.sign({ sub: userId, exp: Math.floor(Date.now() / 1000) + 3600 },
                  JWT_SECRET);
}

function validateKey(key) {
  if (key === '__proto__' || key === 'constructor') {
    throw new Error('invalid key');
  }
  return key;
}

async function fetchSafe(url) {
  try {
    const res = await fetch(url);
    return await res.json();
  } catch (err) {
    console.error('fetch failed:', err.message);
    return null;
  }
}

function goHome(res) {
  res.redirect('/home');
}

module.exports = { app, renderName, issueToken, validateKey, fetchSafe, goHome };
