import express from 'express'
import path from 'path'
import { fileURLToPath } from 'url'
import bodyParser from "body-parser";
import fs from 'fs'
import session from "express-session";
import { readFileSync, writeFileSync, appendFile, appendFileSync } from 'fs'
import { promises as fsPromises } from 'fs'
import axios from 'axios'
import crypto from 'crypto'
import cors from 'cors'
import { promisify } from 'util'
import nodemailer from 'nodemailer'
import validator from 'validator'
import os from 'os'
import figlet from 'figlet'
import dotenv from 'dotenv'
import cookieParser from 'cookie-parser'
import bcrypt from "bcrypt"
import { execFile } from "child_process"
import PDFDocument from 'pdfkit'
import sharp from 'sharp'
import multer from "multer"
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import { body, validationResult } from 'express-validator'
import checkDiskSpace from 'check-disk-space'
import mime from "mime-types";
import { createRequire } from "module";

dotenv.config({ override: false });
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: String(Math.floor(100000 + Math.random() * 900000)),
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.use((err, req, res, next) => {
    console.error(err);
    res.status(err.status || 500).json({
        message: "Ein Fehler ist aufgetreten."
    });
});



const PORT = process.env.PORT || 3000;
const publicPath = path.join(__dirname, 'public');
const indexFile = path.join(__dirname, "index.json");
const indexData = JSON.parse(fs.readFileSync(indexFile, "utf8"));
const require = createRequire(import.meta.url);
const users = require("./users.json");
const PREVIEW_MIME_TYPES = [
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
    "application/pdf",
    "text/plain"
];

async function getShareFile(id, req, res, raw) {
    if (!id) {
        return res.status(404).sendFile(
            path.join(publicPath, "error.html")
        );
    }

    const file = indexData.find(item => item.id === id);

    if (!file || (!req.session.user && !file.shared)) {
        return res.status(404).sendFile(
            path.join(publicPath, "error.html")
        );
    }


    const targetFilePath = path.join(__dirname, "content", file.path)
    const mimeType = mime.lookup(targetFilePath);
    console.log("MimeType: ", mimeType)
    if (!raw && mimeType && PREVIEW_MIME_TYPES.includes(mimeType)) {
        res.setHeader(
            "Content-Disposition",
            `inline; filename="${path.basename(file.path)}"`
        );
    } else {
        res.setHeader(
            "Content-Disposition",
            `attachment; filename="${path.basename(file.path)}"`
        );
    }

    res.status(200).sendFile(targetFilePath);
}

app.get('/share/:id', (req, res) => {
    const id = req.params.id;
    const raw = req.query.raw === 'true'; // Query-Parameter als Boolean

    if (!id) {
        return res.status(404).sendFile("404.html", { root: path.resolve() });
    }

    getShareFile(id, req, res, raw);
});


app.post("/login", (req, res) => {
    const { username, psw } = req.body;

    if (!username || !psw) {
        return res.status(403).json({ success: false, reason: "Missing credentials" });
    }

    const user = users.find(u => u.username === username && u.password === psw);

    if (user) {
        req.session.user = { username: user.username };
        return res.json({ success: true, message: "Login successful" });
    } else {
        return res.status(403).json({ success: false, reason: "Invalid username or password" });
    }
});

app.get("/content", (req, res) => {
    if (req.session.user) {
        res.status(200).send(indexData);
    } else {
        res.status(401).json({ success: false, reason: "Not logged in" });
    }
});


app.use(express.static(publicPath))

app.use((req, res, next) => {
    res.status(404).sendFile(path.join(publicPath, 'error.html'));
});

app.listen(PORT, () => {
    console.log(`[SERVER] Running on Port ${PORT}`);
}).on('error', (e) => {
    console.log("[SERVER] CRITICAL, CAN'T START SERVER:");
    console.error(e);
});
