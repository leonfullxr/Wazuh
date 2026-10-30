import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

for (const route of ['overview', 'alerts', 'queue', 'chains', 'incidents', 'metrics', 'investigate', 'history', 'topics', 'status', 'ai_quality', 'soc_operations']) {
  for (const mode of ['light', 'dark']) {
    test(`${route} ${mode} accessibility`, async ({ page }) => {
      await page.emulateMedia({ reducedMotion: 'reduce' });
      await page.addInitScript((value) => localStorage.setItem('ai-soc-theme', value), mode);
      await page.goto(`/#${route}`);
      await expect(page.locator('main')).toBeVisible();
      const result = await new AxeBuilder({ page }).analyze();
      expect(result.violations.map(v => ({ id: v.id, targets: v.nodes.flatMap(n => n.target) }))).toEqual([]);
    });
  }
}

test('command palette searches within the selected site', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Open search and navigation' })).toBeVisible();
  await page.keyboard.press('Control+k');
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('Search', { exact: true }).fill('1234');
  await dialog.getByRole('option', { name: 'Search Rule: 1234' }).click();
  await expect(page).toHaveURL(/rule_id=1234/);
  await expect(page).toHaveURL(/#alerts$/);
});

test('command keyboard controls restore focus and navigate', async ({ page }) => {
  await page.goto('/#overview');
  const trigger = page.getByRole('button', { name: 'Open search and navigation' });
  await expect(trigger).toBeVisible();
  await trigger.focus();
  await page.keyboard.press('Control+k');
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(trigger).toBeFocused();
  await page.keyboard.press('Control+k');
  await dialog.getByRole('combobox').fill('Queue');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Queue', level: 1 })).toBeVisible();
});

for (const route of ['overview', 'alerts', 'queue', 'chains', 'incidents', 'metrics', 'investigate', 'history', 'topics', 'status', 'ai_quality', 'soc_operations']) {
  test(`${route} fits mobile viewport`, async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto(`/#${route}`);
    await expect(page.locator('main')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}
