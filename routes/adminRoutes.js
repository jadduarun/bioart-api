import express from "express";
import { getProducts } from "../controllers/adminController.js";
import { authenticate } from "../middleware/authMiddleware.js";

const router = express.Router();

router.get("/products", authenticate, getProducts);

export default router;
