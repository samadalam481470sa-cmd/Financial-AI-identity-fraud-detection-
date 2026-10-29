import { chromium } from 'playwright';
import { mkdir } from 'node:fs/promises';

const baseURL = process.env.AEGIS_SCREENSHOT_URL || 'http://127.0.0.1:5173';
const out = 'docs/images';
await mkdir(out, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
const sampleDecision = {
  id: 'synthetic-demo-transaction-0001',
  timestamp: '2026-10-29T12:00:00Z',
  subject_ref: 'synthetic-id-00001',
  action: 'transfer',
  decision: 'hold',
  risk_score: 94,
  reason_codes: ['NEW_DEVICE','HIGH_VALUE','NEW_BENEFICIARY','SIGNED_ACTION_REQUIRED'],
  evidence: { signature_verified: false },
  policy_version: 'continuity-policy-4',
  model_version: 'baseline-rules-4'
};
const sampleCases = [
  { id:'synthetic-case-01', status:'open', created_at:'2026-10-29T12:00:00Z' },
  { id:'synthetic-case-02', status:'investigating', created_at:'2026-10-29T11:30:00Z' },
  { id:'synthetic-case-03', status:'escalated', created_at:'2026-10-29T10:00:00Z' }
];
await page.route('**/v1/**', async route => {
  const url = new URL(route.request().url());
  const path = url.pathname;
  let response = {};
  if (path === '/v1/evaluate') response = sampleDecision;
  else if (path === '/v1/cases') response = { cases: sampleCases };
  else if (path === '/v1/events') response = { events: [sampleDecision] };
  else if (path === '/v1/metrics') response = { counts: { allow: 208, challenge: 17, hold: 9 }, open_cases: 3, model_version: 'baseline-rules-4', policy_version: 'continuity-policy-4' };
  else if (path === '/v1/audit/verify') response = { valid: true, checked: 234, head_hash: 'synthetic-hash', anchored_externally: false };
  else if (path.startsWith('/v1/challenges')) response = { challenge_id:'synthetic', message_to_sign:'synthetic', expires_at:'2026-10-29T12:03:00Z' };
  await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
});
try {
  await page.goto(baseURL, { waitUntil: 'networkidle' });
  await page.locator('input[aria-label="API key"]').fill('synthetic-test-only');
  await page.getByRole('button', { name: 'Load investigations' }).click();
  await page.getByText('208').waitFor();
  await page.screenshot({ path: out + '/dashboard-overview.png', fullPage: true });
  await page.getByRole('button', { name: 'Evaluate unsigned' }).click();
  await page.locator('.score').waitFor({ state: 'visible' });
  await page.screenshot({ path: out + '/fraud-detection-demo.png', fullPage: true });
  console.log('Screenshots captured: dashboard-overview.png, fraud-detection-demo.png');
} finally {
  await browser.close();
}
