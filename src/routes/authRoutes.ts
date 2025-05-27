import { Router } from 'express';

import { register, login, verify , update} from '../controllers/authController';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/verify-token', verify);
router.post('/update-token', update);


export default router;
