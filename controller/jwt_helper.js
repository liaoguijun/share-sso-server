const jwt = require("jsonwebtoken");
const { privateCert } = require("../config").keys;

const ISSUER = "sso";

const genJwtToken = (payload) =>
  new Promise((resolve, reject) => {
    // some of the libraries and libraries written in other language,
    // expect base64 encoded secrets, so sign using the base64 to make
    // jwt useable across all platform and langauage.
    jwt.sign({ ...payload }, ISSUER, (err, token) => {
      if (err) return reject(err);
      return resolve(token);
    });
  });

const verifyJwtToken = (token) => {
  return new Promise((resolve, reject) => {
    // some of the libraries and libraries written in other language,
    // expect base64 encoded secrets, so sign using the base64 to make
    // jwt useable across all platform and langauage.
    jwt.verify(token, ISSUER, (err, decode) => {
      if (err) return reject(err);
      return resolve(decode);
    });
  });
};

module.exports = Object.assign({}, { genJwtToken, verifyJwtToken });
