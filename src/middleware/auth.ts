import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { AuthRequest, AuthToken } from "../types/auth";
import { HttpStatusCode } from "../enums/StatusCodes";
import { decode } from "punycode";

const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

export const authenticateToken = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  console.log('[Auth] User token check - All cookies:', req.cookies);
  const token =
    req.cookies.accessToken ||
    req.cookies.token ||
    req.cookies.companyToken ||
    req.cookies.refreshToken;
  console.log('[Auth] User token found:', token ? 'YES' : 'NO');
  
  if (!token) {
    console.log('[Auth] No user token provided');
    res
      .status(HttpStatusCode.UNAUTHORIZED)
      .json({ error: "No token provided" });
    return;
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as AuthToken;
    const userId = decoded.userId ?? decoded.id ?? decoded.companyId;
    if (!userId) {
      res
        .status(HttpStatusCode.FORBIDDEN)
        .json({ error: "Invalid token payload" });
      return;
    }
    req.user = {
      id: userId,
      email: decoded.email,
      role: decoded.role,
      userType: decoded.userType,
      companyName: decoded.companyName,
    };
    next();
  } catch (error) {
    res
      .status(HttpStatusCode.FORBIDDEN)
      .json({ error: "Invalid or expired token" });
    return;
  }
};

export const authenticateAdminToken = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  console.log('[Auth] Admin token check - All cookies:', req.cookies);
  const token = req.cookies.admintoken;
  console.log('[Auth] Admin token found:', token ? 'YES' : 'NO');
  
  if (!token) {
    console.log('[Auth] No admin token provided');
    res.status(HttpStatusCode.UNAUTHORIZED).json({ error: "No admin token provided" });
    return;
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as AuthToken;
    console.log('[Auth] Token decoded successfully:', { userId: decoded.userId || decoded.id, role: decoded.role });
    
    const userId = decoded.userId ?? decoded.id;
    if (!userId) {
      console.log('[Auth] Invalid token payload - no userId');
      res.status(HttpStatusCode.FORBIDDEN).json({ error: "Invalid token payload" });
      return;
    }
    req.user = {
      id: userId,
      email: decoded.email,
      role: decoded.role,
      userType: decoded.userType,
      companyName: decoded.companyName,
    };
    console.log('[Auth] Admin authentication successful for user:', req.user.email, 'role:', req.user.role);
    next();
  } catch (error) {
    console.log('[Auth] Token verification failed:', error);
    res.status(HttpStatusCode.FORBIDDEN).json({ error: "Invalid or expired token" });
  }
};
export const authorizeRoles = (...allowedRoles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(HttpStatusCode.FORBIDDEN).json({
        error: `Access denied. Required roles: ${allowedRoles.join(", ")}`,
      });
      return;
    }

    next();
  };
};

export const optionalAuth = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  const token =
   req.cookies.accessToken || req.cookies.token || req.cookies.admintoken || req.cookies.companyToken;

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as AuthToken;
      const userId = decoded.userId ?? decoded.id ?? decoded.companyId;
      if (userId) {
        req.user = {
          id: userId,
          email: decoded.email,
          role: decoded.role,
          userType: decoded.userType,
          companyName: decoded.companyName,
        };
      }
    } catch (error) {
      console.log("Optional auth failed:", error);
    }
  }

  next();
};
