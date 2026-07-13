<?php

declare(strict_types=1);

namespace TheColony\OAuth2\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TheColony\OAuth2\ColonyBrand;

final class ColonyBrandTest extends TestCase
{
    #[Test]
    public function currentVariantInheritsCurrentColor(): void
    {
        $svg = ColonyBrand::mark(ColonyBrand::CURRENT, 24);
        $this->assertStringContainsString('<svg', $svg);
        $this->assertStringContainsString('width="24" height="24"', $svg);
        $this->assertStringContainsString('viewBox="0 0 120 120"', $svg);
        $this->assertStringContainsString('currentColor', $svg);
        $this->assertStringNotContainsString('#00ffcc', $svg);
    }

    #[Test]
    public function cyanVariantUsesBrandGradient(): void
    {
        $svg = ColonyBrand::mark(ColonyBrand::CYAN, 32);
        $this->assertStringContainsString('linearGradient', $svg);
        $this->assertStringContainsString(ColonyBrand::CYAN_FROM, $svg);
        $this->assertStringContainsString(ColonyBrand::CYAN_TO, $svg);
        $this->assertStringContainsString('width="32" height="32"', $svg);
    }

    #[Test]
    public function cyanGradientIdsAreUniquePerCall(): void
    {
        $a = ColonyBrand::mark(ColonyBrand::CYAN);
        $b = ColonyBrand::mark(ColonyBrand::CYAN);
        $this->assertSame(1, preg_match('/id="(colony-cyan-\d+)"/', $a, $ma));
        $this->assertSame(1, preg_match('/id="(colony-cyan-\d+)"/', $b, $mb));
        $this->assertNotSame($ma[1], $mb[1], 'Two marks on one page must not share a gradient id.');
    }

    #[Test]
    public function whiteAndBlackVariantsUseSolidColours(): void
    {
        $this->assertStringContainsString('#ffffff', ColonyBrand::mark(ColonyBrand::WHITE));
        $this->assertStringContainsString('#000000', ColonyBrand::mark(ColonyBrand::BLACK));
    }

    #[Test]
    public function titleRendersAsAccessibleLabel(): void
    {
        $svg = ColonyBrand::mark(ColonyBrand::CURRENT, 24, 'Sign in');
        $this->assertStringContainsString('aria-labelledby', $svg);
        $this->assertStringContainsString('<title', $svg);
        $this->assertStringContainsString('Sign in', $svg);
    }

    #[Test]
    public function emptyTitleMarksDecorative(): void
    {
        $svg = ColonyBrand::mark(ColonyBrand::CURRENT, 24, '');
        $this->assertStringContainsString('aria-hidden="true"', $svg);
        $this->assertStringNotContainsString('<title', $svg);
    }

    #[Test]
    public function titleIsHtmlEscaped(): void
    {
        $svg = ColonyBrand::mark(ColonyBrand::CURRENT, 24, '<x>&"');
        $this->assertStringContainsString('&lt;x&gt;', $svg);
        $this->assertStringNotContainsString('<x>', $svg);
    }

    #[Test]
    public function unknownVariantThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ColonyBrand::mark('purple');
    }

    #[Test]
    public function nonPositiveSizeThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ColonyBrand::mark(ColonyBrand::CURRENT, 0);
    }

    /** @return iterable<string, array{string, string}> */
    public static function variantFileProvider(): iterable
    {
        yield 'current' => [ColonyBrand::CURRENT, 'colony-mark.svg'];
        yield 'cyan' => [ColonyBrand::CYAN, 'colony-mark-cyan.svg'];
        yield 'white' => [ColonyBrand::WHITE, 'colony-mark-white.svg'];
        yield 'black' => [ColonyBrand::BLACK, 'colony-mark-black.svg'];
    }

    #[Test]
    #[DataProvider('variantFileProvider')]
    public function assetPathPointsAtAShippedReadableSvg(string $variant, string $expectedFile): void
    {
        $path = ColonyBrand::assetPath($variant);
        $this->assertStringEndsWith('/assets/' . $expectedFile, $path);
        $this->assertFileExists($path);
        $contents = (string) file_get_contents($path);
        $this->assertStringContainsString('<svg', $contents);
    }

    #[Test]
    public function assetPathRejectsUnknownVariant(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ColonyBrand::assetPath('chartreuse');
    }

    #[Test]
    public function dataUriIsBase64Svg(): void
    {
        $uri = ColonyBrand::markDataUri(ColonyBrand::CYAN, 16);
        $this->assertStringStartsWith('data:image/svg+xml;base64,', $uri);
        $decoded = base64_decode(substr($uri, strlen('data:image/svg+xml;base64,')), true);
        $this->assertIsString($decoded);
        $this->assertStringContainsString('<svg', (string) $decoded);
    }

    #[Test]
    public function loginButtonRendersAccessibleAnchor(): void
    {
        $html = ColonyBrand::loginButton('https://thecolony.ai/oauth/authorize?x=1');
        $this->assertStringContainsString('<a href="https://thecolony.ai/oauth/authorize?x=1"', $html);
        $this->assertStringContainsString('role="button"', $html);
        $this->assertStringContainsString('colony-login-button colony-login-button--auto', $html);
        $this->assertStringContainsString(ColonyBrand::DEFAULT_LABEL, $html);
        $this->assertStringContainsString('<svg', $html);
        $this->assertStringContainsString('aria-hidden="true"', $html);
    }

    #[Test]
    public function loginButtonEscapesHrefAndLabel(): void
    {
        $html = ColonyBrand::loginButton('https://x.test/?a=1&b="2"', ['label' => 'Sign in <script>']);
        $this->assertStringContainsString('&amp;b=', $html);
        $this->assertStringContainsString('&quot;2&quot;', $html);
        $this->assertStringContainsString('Sign in &lt;script&gt;', $html);
        $this->assertStringNotContainsString('<script>', $html);
    }

    #[Test]
    public function loginButtonHonoursThemeVariantAndClass(): void
    {
        $html = ColonyBrand::loginButton('https://x.test', [
            'theme' => 'dark',
            'variant' => ColonyBrand::WHITE,
            'class' => 'w-full',
        ]);
        $this->assertStringContainsString('colony-login-button--dark', $html);
        $this->assertStringContainsString('w-full', $html);
        $this->assertStringContainsString('#ffffff', $html);
    }

    #[Test]
    public function loginButtonAppliesSafeExtraAttributes(): void
    {
        $html = ColonyBrand::loginButton('https://x.test', [
            'attributes' => [
                'id' => 'colony-cta',
                'data-track' => 'login & go',
                'hidden' => true,
                'disabled' => false,
                'href' => 'https://evil.test',   // must be ignored
                'class' => 'pwned',               // must be ignored
                'bad attr' => 'x',                // invalid name, ignored
            ],
        ]);
        $this->assertStringContainsString('id="colony-cta"', $html);
        $this->assertStringContainsString('data-track="login &amp; go"', $html);
        $this->assertStringContainsString(' hidden', $html);
        $this->assertStringNotContainsString('disabled', $html);
        $this->assertStringNotContainsString('evil.test', $html);
        $this->assertStringNotContainsString('pwned', $html);
        $this->assertStringNotContainsString('bad attr', $html);
    }

    #[Test]
    public function loginButtonRejectsEmptyHref(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ColonyBrand::loginButton('');
    }

    #[Test]
    public function loginButtonRejectsUnknownTheme(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ColonyBrand::loginButton('https://x.test', ['theme' => 'neon']);
    }

    #[Test]
    public function stylesheetCoversThemes(): void
    {
        $css = ColonyBrand::buttonStylesheet();
        $this->assertStringContainsString('.colony-login-button', $css);
        $this->assertStringContainsString('--light', $css);
        $this->assertStringContainsString('--dark', $css);
        $this->assertStringContainsString('prefers-color-scheme:dark', $css);
        $this->assertStringContainsString('#00ccff', $css);
    }
}
