import 'dotenv/config'
import debug from 'debug'
import express from 'express'
import cors from 'cors'
import { resolve } from 'node:path'
import cookieParser from 'cookie-parser'
import { OAuth2Client } from 'google-auth-library'

const port = process.env.PORT ?? 8081;
const host = process.env.HOST ?? '127.0.0.1';

const logger = debug('app:http');
const app = express()

app.use(cors())
app.use(express.static(resolve("public")))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser(process.env.APP_COOKIE_SECRET));
app.set('view engine', 'hbs');

app.post('/google/auth/callback', async (req, res) => {

  const { g_csrf_token } = req.cookies;

  if (g_csrf_token === req.body.g_csrf_token) {
    const idToken = req.body.credential;
    const client = new OAuth2Client({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    })
    const result = await client.verifyIdToken({
      idToken,
      audience: [process.env.GOOGLE_CLIENT_ID],
    });

    const payload = result.getPayload();
    res.cookie('auth', JSON.stringify(payload), {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      signed: true,
    });

  }

  res.redirect('/');
})

app.post('/sign-out', (req, res) => {
  res.clearCookie('auth');
  res.redirect('/')
})

app.get('/', (req, res) => {
  const callbackUrl = new URL("/google/auth/callback", process.env.APP_BASE_URL).href;
  let auth = req.signedCookies['auth']
  if (auth) {
    auth = JSON.parse(auth);
  }
  res.render('index', { auth, callbackUrl })
})

app.listen(port, host, () => logger(`server is listening on: http://${host}:${port}`))