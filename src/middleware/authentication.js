
import quicker from '../util/quicker.js'
import config from '../config/config.js'
import databaseService from '../service/databaseService.js'
import httpError from '../util/httpError.js'
import responseMessage from '../constant/responseMessage.js'

export default async (request, _res, next) => {
    try {
        const req = request;

        const { cookies } = req

        const { accessToken } = cookies;

        if (accessToken) {
            // Verify Token
            const { userId } = quicker.verifyToken(accessToken, config.ACCESS_TOKEN.SECRET);

            // Find User by id
            const user = await databaseService.findUserById(userId)
            if (user) {
                req.authenticatedUser = user
                return next()
            }
        }

        httpError(next, new Error(responseMessage.UNAUTHORIZED), req, 401)
    } catch (err) {
        httpError(next, err, request, 500)
    }
}
