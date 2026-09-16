// bad_javascript.js
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.get('/admin/users', (req, res) => {
  res.json([]);
});

app.post('/login', (req, res) => {
  const token = jwt.sign({ sub: req.body.user }, 'secret');
  res.json({ token });
});

function render(data) {
  document.getElementById('x').innerHTML = data;
  el.innerHTML = '<b>safe</b>';
}

function setProto(obj, evil) {
  obj.__proto__ = evil;
}

function go(req, res) {
  res.redirect(req.query.next);
  res.redirect('/home');
}

fetch('/api/data').then(r => r.json());
fetch('/api/safe').then(r => r.json()).catch(handleErr);
