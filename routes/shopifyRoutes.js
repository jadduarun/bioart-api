import express from 'express';
import axios from 'axios';
const router = express.Router();

router.get('/products', async (req, res) => {
  try {
    const response = await axios.get(`https://${process.env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-04/products.json`, {
      headers: {
        'X-Shopify-Access-Token': process.env.SHOPIFY_ADMIN_ACCESS_TOKEN,
        'Content-Type': 'application/json',
      },
    });
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching products', error: error.message });
  }
});

export default router;
