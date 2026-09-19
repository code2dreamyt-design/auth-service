import nodemailer from "nodemailer";
import {
  clientUrl,
  emailFrom,
  smtpHost,
  smtpPass,
  smtpPort,
  smtpUser,
} from "../config/env.js";
const transporter = nodemailer.createTransport({
  host: smtpHost,
  port: Number(smtpPort),
  secure: Number(smtpPort) === 465,
  auth: { user: smtpUser, pass: smtpPass },
});
export const sendEmail = async ({ to, subject, html }) => {
  try {
    await transporter.sendMail({
      from: emailFrom,
      to,
      subject,
      html,
    });
  } catch (error) {
    console.log("Email send failed:", error.message);
    throw error;
  }
};

export const sendVerificationEmail = async (user, rawToken) => {
  const link = `${clientUrl}/verify-email/${rawToken}`;

  await sendEmail({
    to: user.email,
    subject: "Verify your email",
    html: `
      <h1>Verify your email</h1>
      <p>Click the link below to verify your email address:</p>
      <a href="${link}">${link}</a>
      <p>This link expires soon — if it's expired, you can request a new one from the app.</p>
    `,
  });
};
export const sendPasswordResetEmail = async (user,rawToken)=>{
    const link = `${clientUrl}/reset-password/${rawToken}`;

    await sendEmail({
        to:user.email,
        subject:"Reset Your Password",
        html: `
      <h1>VReset your password</h1>
      <p>Click the link below to reset your password:</p>
      <a href="${link}">${link}</a>
      <p>This link expires in 10 min — if it's expired, you can request a new one from the app.</p>
    `,
    });
}