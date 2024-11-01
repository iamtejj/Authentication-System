import { Router } from 'express'
import apiController from '../controller/apiController.js';
import authentication from '../middleware/authentication.js';

const router = Router();

router.route('/register').post(apiController.register);

router.route('/confirmation/:token').put(apiController.confirmation);

router.route('/login').post(apiController.login);

router.route('/self-identification').get(authentication, apiController.selfIdentification);

router.route('/logout').put(authentication, apiController.logout);

router.route('/refresh-token').post(apiController.refreshToken);

router.route('/forgot-password').put(apiController.forgotPassword);

router.route('/reset-password/:token').put(apiController.resetPassword);

router.route('/change-password').put(authentication, apiController.changePassword);

export default router