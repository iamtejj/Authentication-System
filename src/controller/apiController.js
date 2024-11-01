import httpResponse from '../util/httpResponse.js'
import responseMessage from '../constant/responseMessage.js'
import httpError from '../util/httpError.js'
import { ValidateChangePasswordBody, ValidateForgotPasswordBody, validateJoiSchema, ValidateLoginBody, ValidateRegisterBody, ValidateResetPasswordBody } from '../service/validationService.js';
import quicker from '../util/quicker.js';
import databaseService from '../service/databaseService.js';
import { EUserRole } from '../constant/userConstant.js';
import config from '../config/config.js';
import emailService from '../service/emailService.js';
import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc.js'

dayjs.extend(utc);
export default {
    demo: (req, res, next) => {
        try {
            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    register: async (req, res, next) => {
        try {
            const { body } = req;
            // Todo:
            //* body validation
            const { error, value } = validateJoiSchema(ValidateRegisterBody, body);
            if (error) {
                httpError(next, error, req, 422);
            }
            //* phone number validation
            const { name, emailAddress, password, phoneNumber, consent } = value
            const { countryCode, internationalNumber, isoCode } = quicker.parsePhoneNumber('+' + phoneNumber);

            if (!countryCode || !internationalNumber || !isoCode) {
                return httpError(next, new Error(responseMessage.INVALID_PHONE_NUMBER), req, 422);
            }
            //* Time zone
            const timezone = quicker.countryTimezone(isoCode);

            if (!timezone || timezone.length === 0) {
                return httpError(next, new Error(responseMessage.INVALID_PHONE_NUMBER), req, 422);
            }

            //* check user existence using email
            const user = await databaseService.findUserByEmailAddress(emailAddress);

            if (user) {
                return httpError(next, new Error(responseMessage.ALREAY_EXIST('user', emailAddress)), req, 422);
            }

            //* Encrpting password
            const encryptedPassword = await quicker.hashPassword(password);
            // * Account Confirmation Object
            const token = quicker.generateRandomId();
            const code = quicker.generateOtp(6);

            // * Preparing Object
            const payload = {
                name,
                emailAddress,
                phoneNumber: {
                    countryCode: countryCode,
                    isoCode: isoCode,
                    internationalNumber: internationalNumber
                },
                accountConfirmation: {
                    status: false,
                    token,
                    code: code,
                    timestamp: null
                },
                passwordReset: {
                    token: null,
                    expiry: null,
                    lastResetAt: null
                },
                lastLoginAt: null,
                role: EUserRole.USER,
                timezone: timezone[0].name,
                password: encryptedPassword,
                consent
            }
            //* creating user
            const newUser = await databaseService.registerUser(payload);
            // * Send Email
            const confirmationUrl = `${config.FRONTEND_URL}/confirmation/${token}?code=${code}`
            const to = [emailAddress]
            const subject = 'Confirm Your Account';
            const text = `Hey ${name}, Please confirm your account by clicking on the link below\n\n${confirmationUrl}`

            emailService.sendEmail(to, subject, text).catch((err) => {
                console.log("emailServie error", err);
            });

            httpResponse(req, res, 201, responseMessage.SUCCESS, { _id: newUser._id });
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    confirmation: async (req, res, next) => {
        try {
            const { params, query } = req;
            // Todo
            //* fetch user by token and code
            const { token } = params;
            const { code } = query;
            const user = await databaseService.findUserByConfirmationTokenAndCode(token, code);
            if (!user) {
                return httpError(next, new Error(responseMessage.INVALID_ACCOUNT_CONFIRMATION_TOKEN_OR_CODE), req, 400)
            }
            //* check if user alreay confirmed
            if (user.accountConfirmation.status) {
                return httpError(next, new Error(responseMessage.ACCOUNT_ALREADY_CONFIRMED), req, 400)
            }
            //* account confirm
            user.accountConfirmation.status = true;
            user.accountConfirmation.timestamp = dayjs().utc().toDate();

            await user.save();
            //* account confirmation email
            const to = [user.emailAddress]
            const subject = 'Account Confirmed';
            const text = `Your Account Has Been Confirmed`

            emailService.sendEmail(to, subject, text).catch((err) => {
                console.log("emailServie error", err);
            });

            httpResponse(req, res, 200, responseMessage.SUCCESS);
        } catch (error) {
            httpError(next, err, req, 500);
        }
    },
    login: async (req, res, next) => {
        try {
            const { body } = req;
            // TO DO
            // * validate and parse body
            const { error, value } = validateJoiSchema(ValidateLoginBody, body);
            if (error) {
                return httpError(next, error, req, 422);
            }
            const { emailAddress, password } = value;
            // * Find user
            const user = await databaseService.findUserByEmailAddress(emailAddress, '+password');
            if (!user) {
                return httpError(next, new Error(responseMessage.NOT_FOUND('user')), req, 404);
            }

            // * validate password
            const isValidPassword = await quicker.comparePassword(password, user.password);
            if (!isValidPassword) {
                return httpError(next, new Error(responseMessage.INVALID_EMAIL_OR_PASSWORD), req, 400);
            }

            // * Access token and refresh token
            const accessToken = quicker.generateToken(
                {
                    userId: user.id
                },
                config.ACCESS_TOKEN.SECRET,
                config.ACCESS_TOKEN.EXPIRY
            );

            const refreshToken = quicker.generateToken(
                {
                    userId: user.id
                },
                config.REFRESH_TOKEN.SECRET,
                config.REFRESH_TOKEN.EXPIRY
            );

            // * Last login information
            user.lastLoginAt = dayjs().utc().toDate();
            await user.save();

            // * Refresh Token Store
            const refreshTokenPayload = {
                token: refreshToken
            }

            await databaseService.createRefreshToken(refreshTokenPayload);


            // * Cookie Send
            const DOMAIN = quicker.getDomainFromUrl(config.SERVER_URL)

            res.cookie('accessToken', accessToken, {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.ACCESS_TOKEN.EXPIRY,
                httpOnly: true,
                secure: false
            }).cookie('refreshToken', refreshToken, {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.REFRESH_TOKEN.EXPIRY,
                httpOnly: true,
                secure: false
            })


            httpResponse(req, res, 200, responseMessage.SUCCESS);
        } catch (err) {
            httpError(next, err, req, 500);
        }
    },
    selfIdentification: (req, res, next) => {
        try {
            const { authenticatedUser } = req
            httpResponse(req, res, 200, responseMessage.SUCCESS, authenticatedUser)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    logout: async (req, res, next) => {
        try {
            const { cookies } = req
            const { refreshToken } = cookies

            if (refreshToken) {
                // db -> delete the refresh token
                await databaseService.deleteRefreshToken(refreshToken);
            }

            const DOMAIN = quicker.getDomainFromUrl(config.SERVER_URL)

            // Cookies clear
            res.clearCookie('accessToken', {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.ACCESS_TOKEN.EXPIRY,
                httpOnly: true,
                secure: false
            })

            res.clearCookie('refreshToken', {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.REFRESH_TOKEN.EXPIRY,
                httpOnly: true,
                secure: false
            });

            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    refreshToken: async (req, res, next) => {
        try {
            const { cookies } = req

            const { refreshToken, accessToken } = cookies;

            if (accessToken) {
                return httpResponse(req, res, 200, responseMessage.SUCCESS, {
                    accessToken
                })
            }

            if (refreshToken) {
                // fetch token from db
                const rft = await databaseService.findRefreshToken(refreshToken);
                if (rft) {
                    const DOMAIN = quicker.getDomainFromUrl(config.SERVER_URL)

                    let userId = null

                    try {
                        const decryptedJwt = quicker.verifyToken(refreshToken, config.REFRESH_TOKEN.SECRET);
                        userId = decryptedJwt.userId
                    } catch (err) {
                        userId = null
                    }

                    if (userId) {
                        // * Access Token
                        const accessToken = quicker.generateToken(
                            {
                                userId: userId
                            },
                            config.ACCESS_TOKEN.SECRET,
                            config.ACCESS_TOKEN.EXPIRY
                        )

                        // Generate new Access Token
                        res.cookie('accessToken', accessToken, {
                            path: '/api/v1',
                            domain: DOMAIN,
                            sameSite: 'strict',
                            maxAge: 1000 * config.ACCESS_TOKEN.EXPIRY,
                            httpOnly: true,
                            secure: !(config.ENV === EApplicationEnvironment.DEVELOPMENT)
                        })

                        return httpResponse(req, res, 200, responseMessage.SUCCESS, {
                            accessToken
                        })
                    }
                }
            }

            httpError(next, new Error(responseMessage.UNAUTHORIZED), req, 401)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    forgotPassword: async (req, res, next) => {
        try {
            // Todo:
            // 1. Parsing Body
            const { body } = req;

            // 2. Validate Body
            const { error, value } = validateJoiSchema(ValidateForgotPasswordBody, body);
            if (error) {
                return httpError(next, error, req, 422)
            }

            const { emailAddress } = value

            // 3. Find User by Email Address
            const user = await databaseService.findUserByEmailAddress(emailAddress)
            if (!user) {
                return httpError(next, new Error(responseMessage.NOT_FOUND('user')), req, 404)
            }

            // 4. Check if user account is confirmed
            if (!user.accountConfirmation.status) {
                return httpError(next, new Error(responseMessage.ACCOUNT_CONFIRMATION_REQUIRED), req, 400)
            }

            // 5. Password Reset token & expiry
            const token = quicker.generateRandomId()
            const expiry = quicker.generateResetPasswordExpiry(15)

            // 6. Update User
            user.passwordReset.token = token
            user.passwordReset.expiry = expiry

            await user.save()

            // 7. Send Email
            const resetUrl = `${config.FRONTEND_URL}/reset-password/${token}`
            const to = [emailAddress]
            const subject = 'Account Password Reset Requested'
            const text = `Hey ${user.name}, Please reset your account password by clicking on the link below\n\nLink will expire within 15 Minutes\n\n${resetUrl}`

            emailService.sendEmail(to, subject, text).catch((err) => {
                console.log("Email service error",err);
            })

            httpResponse(req, res, 200, responseMessage.SUCCESS);
        } catch (err) {
            httpError(next, err, req, 500);
        }
    },
    resetPassword: async (req, res, next) => {
        try {
            // Todo
            // * Body Parsing & Validation
            const { body, params } = req;

            const { token } = params

            const { error, value } = validateJoiSchema(ValidateResetPasswordBody, body);

            if (error) {
                return httpError(next, error, req, 422)
            }

            const { newPassword } = value

            // * Fetch user by token
            const user = await databaseService.findUserByResetToken(token);
            if (!user) {
                return httpError(next, new Error(responseMessage.NOT_FOUND('user')), req, 404)
            }

            // * Check if user account is confirmed
            if (!user.accountConfirmation.status) {
                return httpError(next, new Error(responseMessage.ACCOUNT_CONFIRMATION_REQUIRED), req, 400)
            }

            // * Check expiry of the url
            const storedExpiry = user.passwordReset.expiry
            const currentTimestamp = dayjs().valueOf()

            if (!storedExpiry) {
                return httpError(next, new Error(responseMessage.INVALID_REQUEST), req, 400)
            }

            if (currentTimestamp > storedExpiry) {
                return httpError(next, new Error(responseMessage.EXPIRED_URL), req, 400)
            }

            // * Hash new password
            const hashedPassword = await quicker.hashPassword(newPassword)

            // * User update
            user.password = hashedPassword

            user.passwordReset.token = null
            user.passwordReset.expiry = null
            user.passwordReset.lastResetAt = dayjs().utc().toDate()
            await user.save()

            // * Email send
            const to = [user.emailAddress]
            const subject = 'Account Password Reset'
            const text = `Hey ${user.name}, You account password has been reset successfully.`

            emailService.sendEmail(to, subject, text).catch((err) => {
                console.log("Email service error",err);
            })

            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    changePassword: async (req, res, next) => {
        try {
            // Todo
            // * Body Parsing & Validation
            const { body, authenticatedUser } = req

            const { error, value } = validateJoiSchema(ValidateChangePasswordBody, body);
            if (error) {
                return httpError(next, error, req, 422)
            }

            // * Find User by id
            const user = await databaseService.findUserById(authenticatedUser._id, '+password')
            if (!user) {
                return httpError(next, new Error(responseMessage.NOT_FOUND('user')), req, 404)
            }

            const { newPassword, oldPassword } = value

            // * Check if old password is matching with stored password
            const isPasswordMatching = await quicker.comparePassword(oldPassword, user.password);

            if (!isPasswordMatching) {
                return httpError(next, new Error(responseMessage.INVALID_OLD_PASSWORD), req, 400);
            }

            if (newPassword === oldPassword) {
                return httpError(next, new Error(responseMessage.PASSWORD_MATCHING_WITH_OLD_PASSWORD), req, 400)
            }

            // * Password hash for new password
            const hashedPassword = await quicker.hashPassword(newPassword)

            // * User update
            user.password = hashedPassword
            await user.save()

            // * Email Send
            const to = [user.emailAddress]
            const subject = 'Password Changed'
            const text = `Hey ${user.name}, You account password has been changed successfully.`

            emailService.sendEmail(to, subject, text).catch((err) => {
                console.log("Email service error",err);
            })

            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    }
}