import { getTimezonesForCountry } from "countries-and-timezones";
import { parsePhoneNumber } from "libphonenumber-js"
import bcrypt from 'bcrypt';
import { v4 } from 'uuid'
import { randomInt } from 'crypto'
import jwt from 'jsonwebtoken'
import dayjs from "dayjs";


export default {
    parsePhoneNumber: (phoneNumber) => {
        try {
            const parsedContactNumber = parsePhoneNumber(phoneNumber);
            if (parsedContactNumber) {
                return {
                    countryCode: parsedContactNumber.countryCallingCode,
                    isoCode: parsedContactNumber.country || null,
                    internationalNumber: parsedContactNumber.formatInternational()
                }
            }

            return {
                countryCode: null,
                isoCode: null,
                internationalNumber: null
            }
        } catch (err) {
            return {
                countryCode: null,
                isoCode: null,
                internationalNumber: null
            }
        }
    },
    countryTimezone: (isoCode) => {
        return getTimezonesForCountry(isoCode)
    },
    hashPassword: (password) => {
        return bcrypt.hash(password, 10)
    },
    comparePassword: (attemptedPassword, encPassword) => {
        return bcrypt.compare(attemptedPassword, encPassword)
    },
    generateRandomId: () => v4(),
    generateOtp: (length) => {
        const min = Math.pow(10, length - 1)
        const max = Math.pow(10, length) - 1

        return randomInt(min, max + 1).toString()
    },
    generateToken: (payload, secret, expiry) => {
        return jwt.sign(payload, secret, {
            expiresIn: expiry
        })
    },
    verifyToken: (token, secret) => {
        return jwt.verify(token, secret)
    },
    getDomainFromUrl: (url) => {
        try {
            const parsedUrl = new URL(url)
            return parsedUrl.hostname
        } catch (err) {
            throw err
        }
    },
    generateResetPasswordExpiry: (minute) => {
        return dayjs().valueOf() + minute * 60 * 1000
    }
}