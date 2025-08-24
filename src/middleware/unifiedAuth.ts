import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload } from 'jsonwebtoken';
import { AuthRequest } from "../types/auth";
import { HttpStatusCode } from "../enums/StatusCodes";


interface TokenPayload extends JwtPayload {
    userId?: string;
    companyId?: string;
    email: string;
    role: string;
    userType?: string;
    companyName?: string;
    tokenId?: string;
}

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

const blacklistedTokens = new Set<string>();

const authenticateWithToken = (tokenCookie: string, expectedRole: string, req: AuthRequest, res: Response, next: NextFunction):void =>{
    const token = req.cookies[tokenCookie]
    if(!token){
        res.status(HttpStatusCode.UNAUTHORIZED).json({error:'No token provided'});
        return
    }
    if(blacklistedTokens.has(token)){
        res.status(HttpStatusCode.UNAUTHORIZED).json({error:'Token has been revoked'});
        return
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;
        if(decoded.role!==expectedRole){
            res.status(HttpStatusCode.FORBIDDEN).json({error:'Invalid role for this endpoint'});
            return;
        }
        req.user = {
            id: decoded.userId || decoded.companyId || '',
            email: decoded.email,
            role: decoded.role,
            userType: decoded.userType || 'individual',
            companyName: decoded.companyName
        }
        next();
    } catch (error: any) {
        res.status(HttpStatusCode.FORBIDDEN).json({ error: "Invalid or expired token" });
    return;
    }
}

export const authenticateJobseeker = (req: AuthRequest, res: Response, next: NextFunction): void =>{
    authenticateWithToken('accessToken','jobseeker',req,res,next)
}
export const authenticateCompany = (req: AuthRequest, res: Response, next: NextFunction): void =>{
    authenticateWithToken('companyAccessToken','company',req,res,next);
}
export const authenticateAdmin = (req: AuthRequest, res: Response, next: NextFunction): void => {
  authenticateWithToken('adminAccessToken', 'admin', req, res, next);
};

export const authenticateAnyUser = (req: AuthRequest, res: Response, next: NextFunction): void => {
  const tokens = [
    { cookie: 'accessToken', role: 'jobseeker' },
    { cookie: 'companyAccessToken', role: 'company' },
    { cookie: 'adminAccessToken', role: 'admin' }
  ];

  for (const { cookie, role } of tokens) {
    const token = req.cookies[cookie];
    if (token && !blacklistedTokens.has(token)) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;
        if (decoded.role === role) {
          req.user = {
            id: decoded.userId || decoded.companyId || '',
            email: decoded.email,
            role: decoded.role,
            userType: decoded.userType || 'individual',
            companyName: decoded.companyName,
          };
          next();
          return;
        }
      } catch (error) {
        continue; 
      }
    }
  }
  
  res.status(HttpStatusCode.UNAUTHORIZED).json({ error: "No valid token provided" });
};

export const blacklistToken = (token: string): void => {
  blacklistedTokens.add(token);
};
