import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('a fresh visit starts in light mode and System follows the browser when selected', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Light', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('html')).not.toHaveClass(/dark/);
  await page.getByRole('button', { name: 'System', exact: true }).click();
  await expect(page.locator('html')).toHaveClass(/dark/);
  await page.reload();
  await expect(page.getByRole('button', { name: 'System', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('html')).toHaveClass(/dark/);
  await page.emulateMedia({ colorScheme: 'light' });
  await expect(page.locator('html')).not.toHaveClass(/dark/);
});

test('theme persists and is accessible in light and dark', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  await page.getByRole('button', { name: 'Dark', exact: true }).click();
  await expect(page.locator('html')).toHaveClass(/dark/);
  await page.reload();
  await expect(page.locator('html')).toHaveClass(/dark/);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole('button', { name: 'Light', exact: true }).click();
  await expect(page.locator('html')).not.toHaveClass(/dark/);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test('mobile navigation opens and changes route', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto('/');
  await page.getByRole('button', { name: 'Open navigation' }).click();
  await page.getByRole('dialog').getByRole('link', { name: 'Queue' }).click();
  await expect(page.getByRole('heading', { name: 'Queue', level: 1 })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

for (const theme of ['Light', 'Dark'] as const) {
  test(`${theme} severity fills retain contrast and quiet Queue tags`, async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.setItem('ai-soc-language', 'en');
      const originalFetch = window.fetch;
      window.fetch = async (...args) => {
        const response = await originalFetch(...args);
        const url = new URL(response.url);
        if (!['/v1/workspace/alerts', '/v1/workspace/queue'].includes(url.pathname)) return response;
        const data = await response.clone().json();
        if (url.pathname.endsWith('/alerts') && data.items.length) {
          data.items = [6, 9, 10, 12, null].map((level, index) => ({
            ...data.items[0], alert_key: `synthetic-${index}`, rule_level: level,
            rule_description: `Synthetic severity ${index}`,
          }));
        }
        if (url.pathname.endsWith('/queue') && data.items.length) {
          data.items[0].work_state.status = 'resolved';
          data.items[0].group.disposition = {
            disposition_id: 'synthetic-disposition', label: 'true_positive', reason_code: null,
            note: null, actor_key: 'analyst:mock', at: new Date().toISOString(), propagate_to_members: false,
          };
        }
        return new Response(JSON.stringify(data), { status: response.status, headers: response.headers });
      };
    });
    await page.goto('/#alerts');
    await page.getByRole('button', { name: theme, exact: true }).click();
    const cases = [[3, 'red'], [0, 'green'], [1, 'amber'], [2, 'orange']] as const;
    for (const [index, tone] of cases) {
      const row = page.getByRole('row').filter({ hasText: `Synthetic severity ${index}` });
      const tag = row.locator('.tag');
      await expect(tag).toHaveText(String([6, 9, 10, 12][index]));
      const measure = async () => tag.evaluate((element, toneName) => {
        const parse = (value: string) => {
          const probe = document.createElement('span');
          probe.style.color = value;
          document.body.append(probe);
          const result = getComputedStyle(probe).color.match(/[\d.]+/g)?.map(Number) ?? [];
          probe.remove();
          return [result[0] ?? 0, result[1] ?? 0, result[2] ?? 0, result[3] ?? 1];
        };
        const composite = (top: number[], bottom: number[]) => {
          const alpha = top[3] + bottom[3] * (1 - top[3]);
          return [0, 1, 2].map((i) => (top[i] * top[3] + bottom[i] * bottom[3] * (1 - top[3])) / alpha).concat(alpha);
        };
        const style = getComputedStyle(element);
        const root = getComputedStyle(document.documentElement);
        const token = (part: string) => parse(root.getPropertyValue(`--severity-${toneName}-${part}`));
        let background = [255, 255, 255, 1];
        const ancestors: Element[] = [];
        for (let node: Element | null = element; node; node = node.parentElement) ancestors.unshift(node);
        for (const node of ancestors) background = composite(parse(getComputedStyle(node).backgroundColor), background);
        const foreground = composite(parse(style.color), background);
        const luminance = (rgb: number[]) => rgb.slice(0, 3).map((channel) => {
          const c = channel / 255;
          return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
        }).reduce((sum, channel, i) => sum + channel * [0.2126, 0.7152, 0.0722][i], 0);
        const a = luminance(foreground), b = luminance(background);
        return {
          fill: parse(style.backgroundColor), expectedFill: token('bg'),
          border: parse(style.borderColor), expectedBorder: token('border'),
          text: parse(style.color), expectedText: token('text'),
          contrast: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05),
        };
      }, tone);
      const resting = await measure();
      expect(resting.fill, `${tone} severity fill`).toEqual(resting.expectedFill);
      await expect(tag).toHaveAttribute('data-variant', 'severity');
      await expect(tag).toHaveAttribute('data-tone', tone);
      expect(resting.border).toEqual(resting.expectedBorder);
      expect(resting.text).toEqual(resting.expectedText);
      expect(resting.contrast).toBeGreaterThanOrEqual(4.5);
      await row.hover();
      expect(await row.evaluate((element) => element.matches(':hover'))).toBe(true);
      expect((await measure()).contrast).toBeGreaterThanOrEqual(4.5);
      await page.mouse.move(0, 0);
    }
    const unknown = page.getByRole('row').filter({ hasText: 'Synthetic severity 4' }).locator('.tag');
    await expect(unknown).toHaveAttribute('data-variant', 'quiet');
    await expect(unknown).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
    await page.goto('/#queue');
    const disposition = page.getByText('True positive', { exact: true }).first();
    const status = page.locator('.tag').getByText('Resolved', { exact: true }).first();
    for (const [control, tone] of [[disposition, 'red'], [status, 'green']] as const) {
      await expect(control, `${tone} Queue control remains quiet`).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
      await expect(control).toHaveAttribute('data-tone', tone);
      await expect(control).toHaveAttribute('data-variant', 'quiet');
      const colors = await control.evaluate((element, controlTone) => {
        const style = getComputedStyle(element);
        const root = getComputedStyle(document.documentElement);
        const resolve = (value: string) => {
          const probe = document.createElement('span');
          probe.style.color = value;
          document.body.append(probe);
          const result = getComputedStyle(probe).color;
          probe.remove();
          return result;
        };
        return {
          border: style.borderColor, expectedBorder: resolve(root.getPropertyValue('--tag-neutral-border')),
          text: style.color, expectedText: resolve(root.getPropertyValue(controlTone === 'red' ? '--text' : '--tag-neutral-text')),
        };
      }, tone);
      expect(colors.border).toBe(colors.expectedBorder);
      expect(colors.text).toBe(colors.expectedText);
    }
  });
}
