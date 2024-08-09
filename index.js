const express = require('express');
const multer = require('multer');
const NodeClam = require('clamscan');
const fs = require('fs');
const path = require('path');

const app = express();
const upload = multer({ dest: 'uploads/' }); 

const scanFileForVirus = async (filePath) => {
    try {
        const clamscan = await new NodeClam().init({
            clamdscan: {
                host: '127.0.0.1',  
                port: 3310,         
                timeout: 60000,   
                local_fallback: true,
                path: 'C:\\Program Files\\ClamAV', 
                multiscan: true,
                reload_db: false,
                active: true
            },
            preference: 'clamdscan'
        });

        const { isInfected, viruses } = await clamscan.isInfected(filePath);

        return { isInfected, viruses };
    } catch (err) {
        console.error(`Error scanning file: ${err.message}`);
        throw err;
    }
};

app.post('/upload', upload.single('file'), async (req, res) => {
    const tempFilePath = req.file.path;

    try {
        const { isInfected, viruses } = await scanFileForVirus(tempFilePath);

        if (isInfected) {
            fs.unlink(tempFilePath, (err) => {
                if (err) console.error(`Error deleting infected file: ${err.message}`);
            });
            return res.status(400).send(`File is infected with viruses: ${viruses}`);
        }

        const finalPath = path.join(__dirname, 'uploads', req.file.originalname);
        fs.rename(tempFilePath, finalPath, (err) => {
            if (err) {
                return res.status(500).send('Error saving the file');
            }
            res.send('File uploaded and scanned successfully');
        });
    } catch (err) {
        fs.unlink(tempFilePath, (err) => {
            if (err) console.error(`Error deleting file: ${err.message}`);
        });
        res.status(500).send('Error scanning the file');
    }
});

app.listen(3000, () => {
    console.log('Server running 3000');
});
