import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
    private readonly logger = new Logger(EmailService.name);
    private transporter: nodemailer.Transporter;

    constructor() {
        this.transporter = nodemailer.createTransport({
        host: 'mail.grupoconsiti.com',
        port: 465,
        secure: true,
        name: 'gmail.com',
        auth: {
            user: 'noreply@grupoconsiti.com',
            pass: process.env.MAIL_PASSWOORD,
        },
        tls: {
            rejectUnauthorized: false,
        },
            requireTLS: true,
            logger: true,
            debug: true
        });
    }

    async sendResetEmail(email: string, code: string): Promise<void> {
            console.log(email);
            const mailOptions = {
            from: '"Consiti – No Reply" <noreply@grupoconsiti.com>',
            to: email,
            subject: 'Recuperación de contraseña',
            text: `Tu código de recuperación es: ${code}`,
            html: `<p>Tu código de recuperación es: <strong>${code}</strong></p><p>Este código es válido por 15 minutos.</p>`,
        };

        try {
            const info = await this.transporter.sendMail(mailOptions);
            this.logger.log(`Correo enviado a ${email}`);
            this.logger.debug(`Accepted: ${info.accepted}`);
            this.logger.debug(`Rejected: ${info.rejected}`);
            this.logger.debug(`Response: ${info.response}`);
        } catch (error) {
            this.logger.error(`Error enviando correo: ${error.message}`);
            throw error;
        }
    }
}