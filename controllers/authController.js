import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import User from "../models/User.js";

const generateAccessToken = (user) =>
    jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

const generateRefreshToken = (user) =>
    jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: "30d" });

export const register = async (req, res) => {
    const { email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed });
    await user.save();
    res.json({ message: "User registered" });
};

export const login = async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
        return res.status(401).json({ message: "Invalid credentials" });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    user.refreshToken = refreshToken;
    await user.save();

    res.json({ accessToken, refreshToken });
};

export const refresh = async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: "No token" });

    try {
        const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(payload.id);
        if (!user || user.refreshToken !== refreshToken)
            return res.status(403).json({ message: "Invalid refresh token" });

        const newAccessToken = generateAccessToken(user);
        res.json({ accessToken: newAccessToken });
    } catch {
        res.status(403).json({ message: "Invalid token" });
    }
};

export const logout = async (req, res) => {
    const { refreshToken } = req.body;
    const user = await User.findOne({ refreshToken });
    if (user) {
        user.refreshToken = null;
        await user.save();
    }
    res.json({ message: "Logged out" });
};

export const protectedRoute = async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(403).json({ message: "No token" });

    const token = authHeader.split(" ")[1];
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        res.json({ message: "Protected content", userId: payload.id });
    } catch {
        res.status(403).json({ message: "Invalid token" });
    }
};
