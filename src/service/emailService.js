import { Resend } from "resend"
import config from "../config/config.js";

const resend = new Resend(config.EMAIL_API_KEY)

export default {
    sendEmail: async (to, subject, text) => {
        try {
            await resend.emails.send({
                from: 'Wizangle <onboarding@resend.dev>',
                to,
                subject,
                text
            })
        } catch (err) {
            throw err
        }
    }
}