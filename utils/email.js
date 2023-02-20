const nodemailer = require('nodemailer');
const sendEmail = async (options) => {
  // Create a transporter
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
    //Activate in gmail "less secure app" option
  });

  // Define the email options

  const mailOptions = {
    from: 'Yuval Waitzman <yuvalw@gmail.com>',
    to: options.email,
    subject: options.subject,
    text: options.message,
  };
  // Send the email with nodemailer

  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;
