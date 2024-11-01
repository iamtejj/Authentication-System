import mongoose from 'mongoose'
import config from '../config/config.js'
import userModel from '../model/userModel.js'
import refreshTokenModel from '../model/refreshTokenModel.js'

export default {
    connect: async () => {
        try {
            await mongoose.connect(config.DATABASE_URL)
            return mongoose.connection
        } catch (err) {
            throw err
        }
    },
    findUserByEmailAddress: (emailAddress, select = '') => {
        return userModel
            .findOne({
                emailAddress
            })
            .select(select)
    },
    registerUser: (payload) => {
        return userModel.create(payload)
    },
    findUserById: (id, select = '') => {
        return userModel.findById(id).select(select)
    },
    findUserByConfirmationTokenAndCode: (token, code) => {
        return userModel.findOne({
            'accountConfirmation.token': token,
            'accountConfirmation.code': code
        })
    },
    findUserByResetToken: (token) => {
        return userModel.findOne({
            'passwordReset.token': token
        })
    },
    createRefreshToken: (payload) => {
        return refreshTokenModel.create(payload)
    },
    deleteRefreshToken: (token) => {
        return refreshTokenModel.deleteOne({ token: token })
    },
    findRefreshToken: (token) => {
        return refreshTokenModel.findOne({ token })
    }
}