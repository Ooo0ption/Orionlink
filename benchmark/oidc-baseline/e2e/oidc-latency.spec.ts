import { test, expect } from '@playwright/test';

const ITERATIONS = Number.parseInt(process.env.OIDC_E2E_ITERATIONS || '10', 10);
if (!Number.isInteger(ITERATIONS) || ITERATIONS < 1) {
  throw new Error('OIDC_E2E_ITERATIONS must be a positive integer');
}

test('OIDC flow latency test', async ({ browser }) => {
  // The default remains 10; paper runs set OIDC_E2E_ITERATIONS=100.
  test.setTimeout(ITERATIONS * 30_000);
  for (let i = 1; i <= ITERATIONS; i++) {
    console.log(`Running test iteration ${i}...`);
    
    // 每次都创建一个全新的上下文（禁用缓存，不保留 Cookie/Connection）
    const context = await browser.newContext({
      offline: false,
      javaScriptEnabled: true,
      // 关键：确保每次请求都是全新的
    });
    const page = await context.newPage();
    
    // 1. 访问 RP 首页
    await page.goto('http://localhost:14932/oauth2/');
    
    // 2. 点击 Login 按钮
    await page.click('#login');
    
    // 3. 等待跳转到用户信息页面
    await expect(page.locator('h3')).toHaveText('User Information');
    
    // 4. 等待一小会确保 metrics 上报完成
    await page.waitForTimeout(1000);
    
    console.log(`Iteration ${i} completed.`);
    
    // 关闭上下文以清理连接和缓存
    await context.close();
  }
});
