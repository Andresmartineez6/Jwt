/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcrypt';

import { PrismaClient } from '@prisma/client';

import { Role, signToken, verifyToken } from '../utils/jwt';


const prisma=new PrismaClient();


export const register = async (req: Request, res: Response) => {
  const { email, password, name, role } = req.body;

  if (!email || !password) {
    res.status(400).json({ msg: 'Email and password required' });
    return;
  }

  try {
    const userRole: Role = ['USER', 'ADMIN'].includes(role)
      ? (role as Role)
      : 'USER';

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.auth_users.create({
      data: {
        id: uuidv4(),
        email,
        password: hashedPassword,
        name,
        role: userRole,
      },
    });

    res.status(201).json({ msg: 'User created', userId: user.id });
  } catch (error: any) {
    res.status(500).json({ msg: error.message });
  }
};




export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ msg: 'Email and password required' });
    return;
  }

  try {
    const user = await prisma.auth_users.findUnique({ where: { email } });

    if (!user) {
      res.status(401).json({ msg: 'Invalid credentials' });
      return;
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      res.status(401).json({ msg: 'Invalid credentials' });
      return;
    }

    const token = signToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    res.json({ token });
  } catch (error: any) {
    res.status(500).json({ msg: error.message });
  }
};



export const verify = async (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) {
    res.status(400).json({ msg: 'Token required' });
    return;
  }

  const payload = verifyToken(token);

  if (!payload) {
    res.status(401).json({ valid: false });
    return;
  }

  const user = await prisma.auth_users.findUnique({
    where: { id: payload.userId },
  });

  if (!user) {
    res.status(401).json({ valid: false });
    return;
  }

  res.json({
    valid: true,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });


};




export const update = async (req: Request, res: Response) => {
  
  const {id} = req.params;
  const {email, password, name, role } = req.body;

  try{

    const user = await prisma.auth_users.findUnique({ where: { id } });


    if (!user) {
      res.status(404).json({ msg: 'User not found' });
      return;
    }

    const dataToUpdate: any = {};

    if (email) dataToUpdate.email = email;
    if (name) dataToUpdate.name = name;
    if (role && ['USER', 'ADMIN'].includes(role)) dataToUpdate.role = role;
    if (password) dataToUpdate.password = await bcrypt.hash(password, 10);

    const updatedUser = await prisma.auth_users.update({
      where: {id},
      data: dataToUpdate,
    });

    res.json({
      msg:'User updated',
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        name: updatedUser.name,
        role: updatedUser.role,
      },

    });

  }catch(error:any){
    res.status(500).json({ msg: error.message });
  }

};
