import mongoose from 'mongoose'
import config from '../config/config.js'

const refreshTokenSchema = new mongoose.Schema(
    {
        token: {
            type: String,
            required: true
        }
    },
    { timestamps: true }
)

refreshTokenSchema.index(
    {
        createdAt: -1
    },
    { expireAfterSeconds: config.REFRESH_TOKEN.EXPIRY }
)

export default mongoose.model('refresh-token', refreshTokenSchema)