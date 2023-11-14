const catchError = require("../utils/catchError");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const sendEmail = require("../utils/sendEmail");
const EmailCode = require("../models/EmailCode");
const jwt = require("jsonwebtoken");

const getAll = catchError(async (req, res) => {
  const results = await User.findAll();
  return res.json(results);
});

const create = catchError(async (req, res) => {
  const { email, password, firstName, lastName, country, image, frontBaseUrl } =
    req.body;
  const encriptedPassword = await bcrypt.hash(password, 10);
  const result = await User.create({
    email,
    password: encriptedPassword,
    firstName,
    lastName,
    country,
    image,
  });

  const code = require("crypto").randomBytes(32).toString("hex");

  await EmailCode.create({
    code: code,
    userId: result.id,
  });

  const link = `${frontBaseUrl}/auth/verify_email/${code}`;

  await sendEmail({
    to: email,
    subject: "Verificate email for user app",
    html: `
          <h1>Hello ${firstName} ${lastName}</h1>
          <a href="${link}">${link}</a>
          <b>Thanks for sign up in user app</b>
        `,
  });
  return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  const { firstName, lastName, country, image } = req.body;
  const result = await User.update(
    { firstName, lastName, country, image },
    { where: { id }, returning: true }
  );
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

const verifyCode = catchError(async (req, res) => {
  const { code } = req.params;
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode) return res.status(401).json({ message: "Code not found" });
  const user = await User.findByPk(emailCode.userId);
  user.isVerified = true;
  await user.save();
  await emailCode.destroy();
  return res.json(user);
});

const login = catchError(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  if (!user.isVerified)
    return res.status(401).json({ message: "User not verified" });
  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign({ user }, process.env.TOKEN_SECRET, {
    expiresIn: "1d",
  });
  return res.json({ user, token });
});

const getLoggedUser = catchError(async (req, res) => {
  const user = req.user;
  return res.json(user);
});

const resetPassword = catchError(async (req, res) => {
  const { email, frontBaseUrl } = req.body;
  const user = await User.findOne({ where: { email } });

  if (!user) return res.status(401).json({ mensaje: "Invalid credentials" });

  const code = require("crypto").randomBytes(32).toString("hex");

  await EmailCode.create({
    code: code,
    userId: user.id,
  });

  const link = `${frontBaseUrl}/auth/reset_password/${code}`;

  await sendEmail({
    to: email,
    subject: "Password reset email",
    html: `
        <h1>Hola ${user.firstName} ${user.lastName}</h1>
        <a href="${link}">${link}</a>
        <b>Enter the link to reset the password otherwise skip the message</b>
      `,
  });

  return res.status(201).json({ mensaje: "Sending email" });
});

const newPassword = catchError(async (req, res) => {
  const { code } = req.params;
  const { password } = req.body;
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode) return res.status(401).json({ mensaje: "Invalid or expired code" });
  const encryptedPassword = await bcrypt.hash(password, 10);
  const user = await User.findByPk(emailCode.userId);
  if (!user) return res.status(401).json({ mensaje: "User not found" });

  user.password = encryptedPassword;
  await user.save();
  await emailCode.destroy();

  return res.json({ mensaje: "Password reset successfully" });
});

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyCode,
  login,
  getLoggedUser,
  resetPassword,
  newPassword
};
