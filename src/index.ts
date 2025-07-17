import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createProxyMiddleware } from 'http-proxy-middleware';

dotenv.config();

const app = express();
app.use(cors({
    origin: 'http://localhost:5173', 
    credentials: true
  }));
// app.use(express.json());


app.get('/health', (req, res) => {
    res.json({ message: 'API Gateway is running!' });
  });

  app.use((req, res, next) => {
    console.log(`[Gateway] ${req.method} ${req.url}`);
    next();
  });

  app.use('/api/users', createProxyMiddleware({
    target: 'http://localhost:3000/api/users',
    changeOrigin: true,
    pathRewrite: { '^/api/users': '' }
  }));
  
  app.use('/api/company', createProxyMiddleware({
    target: 'http://localhost:3001/api/company',
    changeOrigin: true,
    pathRewrite: { '^/api/company': '' }
  }));



const PORT = process.env.PORT || 4000;



app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
});