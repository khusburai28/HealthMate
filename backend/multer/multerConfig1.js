import multer from 'multer';

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'upload1/') // specify the directory where files will be stored
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname) // specify the file name
    }
});

const upload1 = multer({ storage: storage });

export default upload1;
