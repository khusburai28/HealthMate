import express from 'express';
import { userSignup, userLogin, getUsers, deleteUser, updateUser, getUserDetails } from '../controller/user-controller.js';
import passport from 'passport';
import '../config/passportConfig.js';
import multer from 'multer';
import { create_journal, getPostsByUsername, update_journal, delete_journal} from '../controller/journal-controller.js';
import { getAnonymousPosts, createAnonymousPost } from '../controller/anonymous-controller.js';
import { createMood, getMoods } from '../controller/mood-controller.js'; 
const router = express.Router();
import upload from '../multer/multerConfig.js';
import upload1 from '../multer/multerConfig1.js';
import { getJournalById } from '../controller/journal-controller.js';
import cors from 'cors';


router.use(cors());

router.post('/signup', upload.single('profilePicture') ,userSignup);
router.post('/login', userLogin);
router.get('/users', getUsers);
router.get('/:username/getuserdetails', getUserDetails);
router.delete('/delete-user/:username', deleteUser);
router.patch('/:username/update-user', updateUser);

router.get('/anonymousPosts', getAnonymousPosts);
router.post('/createAnonymousPosts', createAnonymousPost);


router.post ('/:username', upload1.single('coverPicture'), create_journal);
router.get('/:username/journals', getPostsByUsername);
router.put('/journals/:username/:id', update_journal);
router.delete('/journal-delete/:username/:id', delete_journal);
router.get('/:username/:id', getJournalById);

//passport.authenticate('jwt', { session: false })

router.get ('/api/moods/:username', getMoods);
router.post ('/api/moods/:username', createMood);




export default router; 
