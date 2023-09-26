const express = require("express");

const app = express()

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const apiRouter = require('./apiRouter')
app.use('/api', apiRouter)

module.exports = app