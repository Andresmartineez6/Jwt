import { Router } from 'express';

import { register, login, verify } from '../controllers/authController';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/verify-token', verify);

export default router;
