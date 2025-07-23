import express from "express";
import {
    register,
    login,
    refresh,
    protectedRoute,
    logout,
} from "../controllers/authController.js";
import { authenticate } from "../middleware/authMiddleware.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.get("/protected", authenticate, protectedRoute);
router.post("/logout", logout);

export default router;
