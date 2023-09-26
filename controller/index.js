const uuidv4 = require("uuid/v4");
const Hashids = require("hashids");
const URL = require("url").URL;
const hashids = new Hashids();
const { genJwtToken, verifyJwtToken } = require("./jwt_helper");

const re = /(\S+)\s+(\S+)/;

const AUTH_HEADER = "authorization";
const BEARER_AUTH_SCHEME = "bearer";

function parseAuthHeader(hdrValue) {
  if (typeof hdrValue !== "string") {
    return null;
  }
  const matches = hdrValue.match(re);
  return matches && { scheme: matches[1], value: matches[2] };
}

const fromAuthHeaderWithScheme = function (authScheme) {
  const authSchemeLower = authScheme.toLowerCase();
  return function (request) {
    let token = null;
    if (request.headers[AUTH_HEADER]) {
      const authParams = parseAuthHeader(request.headers[AUTH_HEADER]);
      if (authParams && authSchemeLower === authParams.scheme.toLowerCase()) {
        token = authParams.value;
      }
    }
    return token;
  };
};

const fromAuthHeaderAsBearerToken = function () {
  return fromAuthHeaderWithScheme(BEARER_AUTH_SCHEME);
};

const appTokenFromRequest = fromAuthHeaderAsBearerToken();

// app token to validate the request is coming from the authenticated server only.
const appTokenDB = {
  sso_consumer: "l1Q7zkOL59cRqWBkQ12ZiGVW2DBL",
  simple_sso_consumer: "1g0jJwGmRQhJwvwNOrY4i90kD0m",
};

const alloweOrigin = {
  "http://a.com:10000": true,
  "http://b.com:10000": true,
  "http://c.com:10000": true,
};

const deHyphenatedUUID = () => uuidv4().replace(/-/gi, "");
const encodedId = () => hashids.encodeHex(deHyphenatedUUID());

// A temporary cahce to store all the application that has login using the current session.
// It can be useful for variuos audit purpose
const sessionUser = {};
const sessionApp = {};

const originAppName = {
  "http://a.com:10000": "sso_a",
  "http://b.com:10000": "sso_b",
  "http://c.com:10000": "sso_c",
};

const userDB = {
  "ben@krquant.com": {
    password: "abcd1234",
    userId: encodedId(), // incase you dont want to share the user-email.
    appPolicy: {
      sso_a: { role: "admin", shareEmail: true },
      sso_b: { role: "admin", shareEmail: true },
      sso_c: { role: "admin", shareEmail: true },
    },
  },
};

// these token are for the validation purpose
const intrmTokenCache = {};

const fillIntrmTokenCache = (origin, sessionId, ticket) => {
  intrmTokenCache[ticket] = [sessionId, originAppName[origin]];
};

const storeApplicationInCache = (origin, sessionId, ticket) => {
  if (sessionApp[sessionId] == null) {
    sessionApp[sessionId] = {
      [originAppName[origin]]: true,
    };
    fillIntrmTokenCache(origin, sessionId, ticket);
  } else {
    sessionApp[sessionId][originAppName[origin]] = true;
    fillIntrmTokenCache(origin, sessionId, ticket);
  }
};

const generatePayload = (ticket) => {
  const globalSessionToken = intrmTokenCache[ticket][0];
  const appName = intrmTokenCache[ticket][1];
  const userEmail = sessionUser[globalSessionToken];
  const user = userDB[userEmail];
  const appPolicy = user.appPolicy[appName];
  const email = appPolicy.shareEmail === true ? userEmail : undefined;
  const payload = {
    ...{ ...appPolicy },
    ...{
      email,
      shareEmail: undefined,
      uid: user.userId,
      // global SessionID for the logout functionality.
      globalSessionID: globalSessionToken,
    },
  };
  return payload;
};

const verifySsoToken = async (req, res, next) => {
  // const appToken = appTokenFromRequest(req);
  const { ticket } = req.body;
  if (
    // appToken == null ||
    ticket == null ||
    intrmTokenCache[ticket] == null
  ) {
    return res.status(400).json({ message: "badRequest" });
  }

  // if the appToken is present and check if it's valid for the application
  const appName = intrmTokenCache[ticket][1];
  const globalSessionToken = intrmTokenCache[ticket][0];
  if (
    // appToken !== appTokenDB[appName] ||
    sessionApp[globalSessionToken][appName] !== true
  ) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  // checking if the token passed has been generated
  const payload = generatePayload(ticket);

  const token = await genJwtToken(payload);
  // delete the itremCache key for no futher use,
  delete intrmTokenCache[ticket];
  return res
    .status(200)
    .json({ status: 0, message: "success", data: { token } });
};

const login = (req, res, next) => {
  const { email, password, serviceURL } = req.body;   // c.com
  if (!(userDB[email] && password === userDB[email].password)) {
    return res.status(404).json({
      status: 1,
      message: "Invalid email and password",
    });
  }

  if (!serviceURL) {
    return res.status(404).json({
      status: 1,
      message: "Invalid serviceURL",
    });
  }
  const url = new URL(serviceURL);

  if (alloweOrigin[url.origin] !== true) {
    // url.origin b.com
    return res
      .status(400)
      .json({ message: "Your are not allowed to access the sso-server" });
  }

  const sessionId = encodedId();
  sessionUser[sessionId] = email;
  const ticket = encodedId();
  storeApplicationInCache(url.origin, sessionId, ticket);
  return res.json({
    status: 0,
    message: "success",
    data: {
      ticket,
      sessionId
    },
  });
};

const userInfo = async (req, res, next) => {
  try {
    const { token } = req.headers;
    const decode = await verifyJwtToken(token);
    return res.status(200).json({
      status: 0,
      message: "success",
      data: decode,
    });
  } catch (err) {}
  return res.status(401).json({ message: "Unauthorized" });
};

const getServiceTicket = async (req, res, next) => {
  try {
    const { serviceURL } = req.body;
    const decode = await verifyJwtToken(token);
    return res.status(200).json({
      status: 0,
      message: "success",
      data: decode,
    });
  } catch (err) {}
  return res.status(401).json({ message: "Unauthorized" });
};

module.exports = Object.assign({}, { login, verifySsoToken, userInfo, getServiceTicket });
