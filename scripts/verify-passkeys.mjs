import { chromium } from 'playwright';

const baseURL = 'http://localhost:5173';
const browser = await chromium.launch({ headless: true });
let page;
try {
  const context = await browser.newContext({viewport:{width:1440,height:1100}});
  page = await context.newPage();
  const session = await context.newCDPSession(page);
  await session.send('WebAuthn.enable');
  await session.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  const backendErrors = [];
  page.on('console', message => { if(message.type()==='error') backendErrors.push(message.text()); });
  await page.goto(baseURL, {waitUntil:'networkidle'});
  await page.locator('input[aria-label="API key"]').fill('local-web-authn-e2e-key');
  await page.getByRole('button',{name:'1. Synthetic proofing grant'}).click();
  await page.getByText('Synthetic-only enrollment grant recorded.',{exact:false}).waitFor({timeout:15000});
  await page.getByRole('button',{name:'2. Register WebAuthn passkey'}).click();
  await page.getByText('WebAuthn passkey enrolled:',{exact:false}).waitFor({timeout:15000});

  const amount=page.locator('input[type="number"]').nth(0);
  await amount.fill('15');
  await page.locator('input[type="number"]').nth(1).fill('0');
  await page.locator('input[type="number"]').nth(2).fill('0');
  await page.locator('input[type="checkbox"]').nth(0).uncheck();
  await page.locator('input[type="checkbox"]').nth(1).uncheck();

  await page.getByRole('button',{name:'Evaluate unsigned'}).click();
  await page.locator('.decision.hold').waitFor({timeout:15000});
  await page.getByRole('button',{name:'Evaluate with passkey'}).click();
  await page.locator('.decision.allow').waitFor({timeout:20000});
  await page.getByText('Server verified WebAuthn assertion: true',{exact:false}).waitFor({timeout:15000});
  await page.getByText('Audit chain:').waitFor({timeout:15000});
  console.log('Browser security E2E: real WebAuthn browser credential enrollment, unsigned HOLD, signed ALLOW, chain verified');
  if (backendErrors.length) console.log('Browser console warnings/errors:',backendErrors.slice(0,4));
} catch(e){
  if (page) {
    await page.screenshot({path:'/tmp/aegis-passkey-failure.png',fullPage:true}).catch(()=>{});
    console.log('Page:',await page.locator('body').innerText().catch(()=>'unavailable'));
  }
  throw e;
} finally {
  await browser.close();
}
