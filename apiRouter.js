const express = require('express')
const controller = require('./controller')

const apiRouter = express.Router()

// 登录接口
apiRouter.post('/login', controller.login)

// 验证ticket
apiRouter.post('/verifyTicket', controller.verifySsoToken)

// 用户信息
apiRouter.post('/userInfo', controller.userInfo)

// 登录后获取服务的ticket
apiRouter.post('/getServiceTicket', controller.getServiceTicket)

module.exports = apiRouter