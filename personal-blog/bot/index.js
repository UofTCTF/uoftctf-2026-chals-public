const express = require('express');
const puppeteer = require('puppeteer-core');

const PORT = process.env.PORT || 4000;
const APP_HOST = process.env.APP_HOST || 'http://localhost:3000';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || process.env.ADMIN_PASSWORD || 'adminpass';
const BROWSER_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium';

const app = express();
app.use(express.json());

let browserPromise = null;

async function getBrowser() {
  if (!browserPromise) {
    browserPromise = puppeteer.launch({
      headless: 'new',
      executablePath: BROWSER_PATH,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
  }
  return browserPromise;
}

function isLocalUrl(target) {
  try {
    const url = new URL(target);
    return url.origin === APP_HOST;
  } catch (err) {
    return false;
  }
}

async function loginAndVisit(targetUrl) {
  const browser = await getBrowser();
  const context = browser.createBrowserContext
    ? await browser.createBrowserContext()
    : await browser.createIncognitoBrowserContext();
  const page = await context.newPage();
  try {
    page.setDefaultTimeout(10000);

    await page.goto(`${APP_HOST}/login`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', ADMIN_USER, { delay: 40 });
    await page.type('input[name="password"]', ADMIN_PASS, { delay: 40 });
    await Promise.all([
      page.click('button[type="submit"]'),
      page.waitForNavigation({ waitUntil: 'networkidle2' })
    ]);

    await page.goto(targetUrl, { waitUntil: 'networkidle2' });
    await new Promise((resolve) => setTimeout(resolve, 6000));
  } finally {
    await page.close();
    await context.close();
  }
}

app.post('/visit', async (req, res) => {
  const target = String(req.body.url || '');
  if (!isLocalUrl(target)) {
    return res.status(400).json({ ok: false, error: 'invalid url' });
  }
  loginAndVisit(target).catch((err) => {
    console.log(err);
  });
  return res.status(202).json({ ok: true, status: 'started' });
});

app.listen(PORT, () => {
  console.log(`admin bot listening on ${PORT}`);
});
