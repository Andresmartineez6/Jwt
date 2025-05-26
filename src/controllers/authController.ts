/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';

import { Role, signToken, verifyToken } from '../utils/jwt';

const prisma = new PrismaClient();

export const register = async (req: Request, res: Response) => {
  const { email, password, name, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ msg: 'Email and password required' });
  }

  try {
    const userRole: Role = ['USER', 'ADMIN'].includes(role)
      ? (role as Role)
      : 'USER';

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.usersAuth.create({
      data: { email, password: hashedPassword, name, role: userRole },
    });

    return res.status(201).json({ msg: 'User created', userId: user.id });
  } catch (error: any) {
    return res.status(500).json({ msg: error.message });
  }
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ msg: 'Email and password required' });
  }

  try {
    const user = await prisma.usersAuth.findUnique({ where: { email } });

    if (!user) return res.status(401).json({ msg: 'Invalid credentials' });

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ msg: 'Invalid credentials' });
    }

    const token = signToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    return res.json({ token });
  } catch (error: any) {
    return res.status(500).json({ msg: error.message });
  }
};

export const verify = async (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) return res.status(400).json({ msg: 'Token required' });

  const payload = verifyToken(token);

  if (!payload) return res.status(401).json({ valid: false });

  const user = await prisma.user.findUnique({ where: { id: payload.userId } });

  if (!user) return res.status(401).json({ valid: false });

  return res.json({
    valid: true,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
};
