import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import User from "../models/User.js";
import Session from "../models/Session.js";

const generateAccessToken = (user) =>
    jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "15m" });

const generateTokenId = () => crypto.randomBytes(32).toString("hex");

const hashToken = (tokenId) => crypto.createHash("sha256").update(tokenId).digest("hex");

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

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    const tokenId = generateTokenId();
    const tokenHash = hashToken(tokenId);

    await Session.create({ userId: user._id, tokenHash });

    res.cookie("session", tokenId, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const accessToken = generateAccessToken(user);
    res.json({ accessToken });
};

export const refresh = async (req, res) => {
    const sessionId = req.cookies?.session;
    if (!sessionId) return res.status(401).json({ message: "No session ID" });

    const hashed = hashToken(sessionId);
    const session = await Session.findOne({ tokenHash: hashed });

    if (!session) return res.status(403).json({ message: "Invalid session" });

    const user = await User.findById(session.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    await Session.deleteOne({ _id: session._id });

    const newTokenId = generateTokenId();
    const newHash = hashToken(newTokenId);
    await Session.create({ userId: user._id, tokenHash: newHash });

    res.cookie("session", newTokenId, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const newAccessToken = generateAccessToken(user);
    res.json({ accessToken: newAccessToken });
};

export const logout = async (req, res) => {
    const sessionId = req.cookies?.session;
    if (sessionId) {
        const tokenHash = hashToken(sessionId);
        await Session.deleteOne({ tokenHash });
    }

    res.clearCookie("session", {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
    });

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
        res.status(403).json({ message: "Invalid or expired token" });
    }
};
