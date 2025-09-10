import 'reflect-metadata';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';

import {
  authenticateJobseeker,
  authenticateCompany,
  authenticateAdmin,
  authenticateAnyUser,
  blacklistToken,
} from './middleware/unifiedAuth';

import { AuthRequest } from './types/auth';
import { HttpStatusCode } from './enums/StatusCodes';

dotenv.config();

const app = express();

app.use(express.json({limit:'20mb'}));
app.use(express.raw({ type: 'multipart/form-data', limit: '10mb' }));
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true, 
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['set-cookie']
}));

app.use(cookieParser());

app.use((req, res, next) => {
  console.log('🔍 Incoming request:', {
    path: req.path,
    method: req.method,
    cookies: req.cookies,
    headers: req.headers
  });
  next();
});

app.get('/health', (req: Request, res: Response) => {
  res.json({ message: 'API Gateway is running!' });
});

app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`[Gateway] ${req.method} ${req.url}`);
  next();
});

app.use('/api/users/me', async (req: Request, res: Response) => {

  if (req.cookies.adminAccessToken && !req.cookies.accessToken && !req.cookies.companyAccessToken) {
    try {
      const headers: any = {
        'Content-Type': 'application/json',
      };

      if (req.headers.cookie) {
        headers['Cookie'] = req.headers.cookie;
      }

      const response = await fetch(
        'http://localhost:3000/api/users/admin/me',
        {
          method: req.method,
          headers: headers,
        },
      );

      const data = await response.json();
      res.status(response.status).json(data);
      return;
    } catch (error: any) {
      console.log('[Gateway] Error forwarding admin me:', error.message);
    
    }
  }
  req.url = '/me'; 
  return authenticateAnyUser(req as AuthRequest, res, async () => {
    try {
      const headers: any = { 'Content-Type': 'application/json' };

      if ((req as AuthRequest).user) {
        headers['x-user-id'] = (req as AuthRequest).user!.id;
        headers['x-user-email'] = (req as AuthRequest).user!.email;
        headers['x-user-role'] = (req as AuthRequest).user!.role;
        headers['x-user-type'] = (req as AuthRequest).user!.userType;
      }

      const response = await fetch(
        'http://localhost:3000/api/users/me',
        {
          method: req.method,
          headers: headers,
        },
      );

      const data = await response.json();
      res.status(response.status).json(data);
    } catch (error: any) {
      res
        .status(HttpStatusCode.INTERNAL_SERVER_ERROR)
        .json({ error: 'Service unavailable' });
      return;
    }
  });
});

app.post('/api/users/admin/login', async (req: Request, res: Response) => {
  try {
    const response = await fetch('http://localhost:3000/api/users/admin/login', {
      method: 'POST',
      body: JSON.stringify(req.body),
      headers: { 'Content-Type': 'application/json' },
     
    });
    
    const data = await response.json();
    
    console.log('[Gateway] 5. Headers from user-service:', response.headers);

    const setCookieHeaders = response.headers.getSetCookie();
    console.log('[Gateway] 6. Extracted Set-Cookie headers:', setCookieHeaders);

    if (setCookieHeaders.length > 0) {
      res.setHeader('Set-Cookie', setCookieHeaders);
      console.log('[Gateway] 7. Set-Cookie header is being forwarded to the client.');
    } else {
      console.log('[Gateway] 7. No Set-Cookie header found from user-service.');
    }
    res.status(response.status).json(data);
  } catch (e: any) {
    console.error('[Gateway] Error in admin login route:', e.message);
    res.status(HttpStatusCode.INTERNAL_SERVER_ERROR).json({ error: 'Service unavailable' });
  }
});

app.use('/api/users/admin', 
  (req: Request, res: Response, next: NextFunction) => {
    console.log('[Gateway] ADMIN ROUTE HIT:', req.method, req.url);
    next();
  },
  authenticateAdmin,
  async (req: AuthRequest, res: Response) => {
    try {

      const headers: any = {
        'Content-Type': 'application/json',
      };

      if (req.user) {
        headers['x-user-id'] = req.user.id;
        headers['x-user-email'] = req.user.email;
        headers['x-user-role'] = req.user.role;
      }

      const response = await fetch(
        `http://localhost:3000/api/users/admin${req.url}`,
        {
          method: req.method,
          body: req.body ? JSON.stringify(req.body) : undefined,
          headers: headers,
        },
      );

      const data = await response.json();
      
      const setCookieHeaders = response.headers.getSetCookie();
      if (setCookieHeaders.length > 0) {
        res.setHeader('Set-Cookie', setCookieHeaders);
      }
      
      res.status(response.status).json(data);
    } catch (error: any) {
      res
        .status(HttpStatusCode.INTERNAL_SERVER_ERROR)
        .json({ error: 'Service unavailable' });
      return; 
    }
  },
);

app.post('/api/users/refresh-token', async (req: Request, res: Response) => {
  try {
    const response = await fetch('http://localhost:3000/api/users/refresh-token', {
      method: 'POST',
      body: JSON.stringify(req.body),
      headers: {
        'Content-Type': 'application/json',
        'Cookie': req.headers.cookie || ''
      },
    });
    
    const data = await response.json();
    const setCookieHeaders = response.headers.getSetCookie();
    if (setCookieHeaders.length > 0) {
      res.setHeader('Set-Cookie', setCookieHeaders);
    }
    
    res.status(response.status).json(data);
  } catch (error: unknown) {
    res.status(HttpStatusCode.INTERNAL_SERVER_ERROR).json({ error: 'Service unavailable' });
  }
});

app.use('/api/users', async (req: Request, res: Response) => {
  const publicRoutes = ['/login','/register','/generate-otp','/verify-otp','/forgot-password','/reset-password','/refresh-token','/google-auth'];

  if (publicRoutes.includes(req.url) && req.method === 'POST') {
    try {
      console.log('Gateway forwarding public route to user-service');
      const response = await fetch(`http://localhost:3000/api/users${req.url}`, {
        method: 'POST',
        body: JSON.stringify(req.body),
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await response.json();
      const setCookieHeaders = response.headers.getSetCookie();
      if (setCookieHeaders.length > 0) {
        res.setHeader('Set-Cookie', setCookieHeaders);
      }
      res.status(response.status).json(data);
      return;
    } catch (error) {
      res.status(HttpStatusCode.INTERNAL_SERVER_ERROR).json({ error: 'Service unavailable' });
      return; 
    }
  }
  
  return authenticateJobseeker(req as AuthRequest, res, async () => {
    try {
      const headers: any = { 'Content-Type': 'application/json' };

      if ((req as AuthRequest).user) {
        headers['x-user-id'] = (req as AuthRequest).user!.id;
        headers['x-user-email'] = (req as AuthRequest).user!.email;
        headers['x-user-role'] = (req as AuthRequest).user!.role;
        headers['x-user-type'] = (req as AuthRequest).user!.userType;
      }

      const response = await fetch(
        `http://localhost:3000/api/users${req.url}`,
        {
          method: req.method,
          body: req.body ? JSON.stringify(req.body) : undefined,
          headers: headers,
        },
      );

      const data = await response.json();

      const setCookieHeaders = response.headers.getSetCookie();
      if (setCookieHeaders.length > 0) {
        res.setHeader('Set-Cookie', setCookieHeaders);
      }
      
      res.status(response.status).json(data);
    } catch (error: any) {
      res.status(HttpStatusCode.INTERNAL_SERVER_ERROR).json({ error: 'Service unavailable' });
      return; 
    }
  });
});

app.use('/api/profile',authenticateJobseeker,async (req: AuthRequest, res: Response) => {
    try {
      const headers: any = {};
      const incomingType = req.headers['content-type'] as string | undefined;
      if (incomingType) {
        headers['Content-Type'] = incomingType;
      } else {
        headers['Content-Type'] = 'application/json';
      }

      if (req.user) {
        headers['x-user-id'] = req.user.id;
        headers['x-user-email'] = req.user.email;
        headers['x-user-role'] = req.user.role;
      }

      const response = await fetch(
        `http://localhost:3000/api/profile${req.url}`,
        {
          method: req.method,
          body: headers['Content-Type']?.includes('application/json') && req.body ? JSON.stringify(req.body) : (req as any).rawBody || req.body,
          headers: headers,
        },
      )
      const data = await response.json();
      res.status(response.status).json(data);
    } catch (error: unknown) {
      res.status(HttpStatusCode.INTERNAL_SERVER_ERROR).json({ error: 'Service unavailable' });
      return; 
    }
  },
);

app.use('/api/company/admin', 
  authenticateAdmin,
  async (req: AuthRequest, res: Response) => {
    try {
      const headers: any = {
        'Content-Type': 'application/json',
      };

      if (req.user) {
        headers['x-user-id'] = req.user.id;
        headers['x-user-email'] = req.user.email;
        headers['x-user-role'] = req.user.role;
      }

      const response = await fetch(
        `http://localhost:3001/api/company/admin${req.url}`,
        {
          method: req.method,
          body: req.body ? JSON.stringify(req.body) : undefined,
          headers: headers,
        },
      );

      const data = await response.json();
      res.status(response.status).json(data);
    } catch (error: unknown) {
      res.status(HttpStatusCode.INTERNAL_SERVER_ERROR).json({ error: 'Service unavailable' });
      return;
    }
  },
);

app.use('/api/company', async (req: Request, res: Response) => {
  const publicCompanyRoutes = ['/login','/register','/generate-otp','/verify-otp','/resend-otp','/logout','/refresh-token'];
  if (publicCompanyRoutes.includes(req.url) && req.method === 'POST') {
    try {
      console.log('[Gateway] Forwarding company login to company-service');
      const response = await fetch(
        `http://localhost:3001/api/company${req.url}`,
        {
          method: 'POST',
          body: JSON.stringify(req.body),
          headers: { 'Content-Type': 'application/json' },
        },
      );
      const data = await response.json();
      const setCookieHeaders = response.headers.getSetCookie();
      if (setCookieHeaders.length > 0) {
        res.setHeader('Set-Cookie', setCookieHeaders);
      }

      res.status(response.status).json(data);
      return;
    } catch (error) {
      res
        .status(HttpStatusCode.INTERNAL_SERVER_ERROR)
        .json({ error: 'Service unavailable' });
      return;
    }
  }
  
  return authenticateCompany(req as AuthRequest, res, async () => {
    try {
      const headers: any = { 'Content-Type': 'application/json' };

      if ((req as AuthRequest).user) {
        headers['x-user-id'] = (req as AuthRequest).user!.id;
        headers['x-user-email'] = (req as AuthRequest).user!.email;
        headers['x-user-role'] = (req as AuthRequest).user!.role;
        headers['x-user-type'] = (req as AuthRequest).user!.userType;
        if ((req as AuthRequest).user!.companyName) {
          headers['x-company-name'] = (req as AuthRequest).user!.companyName;
        }
      }

      const response = await fetch(
        `http://localhost:3001/api/company${req.url}`,
        {
          method: req.method,
          body: req.body ? JSON.stringify(req.body) : undefined,
          headers: headers,
        },
      );

      const data = await response.json();
      res.status(response.status).json(data);
    } catch (error: any) {
      res
        .status(HttpStatusCode.INTERNAL_SERVER_ERROR)
        .json({ error: 'Service unavailable' });
      return; 
    }
  }); 
});

app.use('/api/jobs', authenticateAnyUser, async (req: AuthRequest, res: Response) => {
  try {
    console.log('🔍 Gateway: Jobs route hit');
    console.log('🔍 Gateway: req.method:', req.method);
    console.log('🔍 Gateway: req.url:', req.url);
    console.log('🔍 Gateway: req.headers:', req.headers);
    console.log('🔍 Gateway: req.user:', req.user);

    const headers: any = {};
    if (req.headers['content-type']) {
      headers['content-type'] = req.headers['content-type'];
    }

    if (req.user) {
      headers['x-user-id'] = req.user.id;
      headers['x-user-email'] = req.user.email;
      headers['x-user-role'] = req.user.role;
      console.log('🔍 Gateway: Added user headers:', headers);
    }

    const jobServiceUrl = `http://localhost:3002/api/jobs${req.url}`;

    // Handle multipart/form-data differently
    let body;
    if (req.headers['content-type']?.includes('multipart/form-data')) {
      // For file uploads, pass the raw body
      body = (req as any).rawBody || req.body;
    } else {
      // For JSON requests, stringify the body
      body = req.body ? JSON.stringify(req.body) : undefined;
    }

    const response = await fetch(jobServiceUrl, {
      method: req.method,
      body: body,
      headers: headers,
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (error: unknown) {
    res.status(HttpStatusCode.INTERNAL_SERVER_ERROR).json({ error: 'Service unavailable' });
    return;
  }
});

app.post('/api/logout', async (req: AuthRequest, res: Response) => {
  try {
    const accessToken = req.cookies.accessToken;
    const companyAccessToken = req.cookies.companyAccessToken;
    const adminAccessToken = req.cookies.adminAccessToken;
    if (accessToken) {
      blacklistToken(accessToken);
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
    } else if (companyAccessToken) {
      blacklistToken(companyAccessToken);
      res.clearCookie('companyAccessToken');
      res.clearCookie('companyRefreshToken');
    } else if (adminAccessToken) {
      blacklistToken(adminAccessToken);
      res.clearCookie('adminAccessToken');
      res.clearCookie('adminRefreshToken');
    }

    res.json({ message: 'Logged out successfully' });
  } catch (error: any) {
    res.status(HttpStatusCode.INTERNAL_SERVER_ERROR).json({ error: 'Logout failed' });
  }
});

const PORT = process.env.PORT || 4000;

process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');

  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
});