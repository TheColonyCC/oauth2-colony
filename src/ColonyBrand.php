<?php

declare(strict_types=1);

namespace TheColony\OAuth2;

/**
 * Brand assets for "Log in with the Colony".
 *
 * The Colony mark is shipped in four colour variants and this class renders
 * an accessible, theme-aware login button so consumers don't have to copy
 * SVGs or hand-write markup.
 *
 * The default variant, {@see ColonyBrand::CURRENT}, paints with `currentColor`,
 * so the mark inherits the surrounding text colour — drop it on a light or dark
 * surface and it stays legible without picking a file. Use the fixed colour
 * variants ({@see ColonyBrand::CYAN}, {@see ColonyBrand::WHITE},
 * {@see ColonyBrand::BLACK}) only where `currentColor` cannot reach: CSS
 * `background-image`, an `<img src>`, or HTML email.
 *
 * Nothing here touches the network or the OAuth flow; it is presentation only.
 */
final class ColonyBrand
{
    /** Adaptive: inherits `currentColor` (recommended). */
    public const CURRENT = 'current';
    /** Brand cyan gradient (#00ffcc -> #00ccff). */
    public const CYAN = 'cyan';
    /** Solid white — for dark or coloured backgrounds. */
    public const WHITE = 'white';
    /** Solid black — for light backgrounds. */
    public const BLACK = 'black';

    /** @var list<string> */
    public const VARIANTS = [self::CURRENT, self::CYAN, self::WHITE, self::BLACK];

    /** Brand cyan gradient endpoints. */
    public const CYAN_FROM = '#00ffcc';
    public const CYAN_TO = '#00ccff';

    /** Recommended, accessible default button label. */
    public const DEFAULT_LABEL = 'Log in with the Colony';

    /** @var list<string> */
    public const THEMES = ['auto', 'light', 'dark'];

    /** Ensures unique gradient ids when several cyan marks share one page. */
    private static int $seq = 0;

    /**
     * Inline SVG for the Colony mark, ready to echo into a page.
     *
     * @param string $variant one of {@see ColonyBrand::VARIANTS}
     * @param int    $size    rendered width/height in pixels (> 0)
     * @param string $title   accessible label; pass '' for a decorative mark
     *
     * @throws \InvalidArgumentException for an unknown variant or a non-positive size
     */
    public static function mark(string $variant = self::CURRENT, int $size = 24, string $title = 'The Colony'): string
    {
        if (!in_array($variant, self::VARIANTS, true)) {
            throw new \InvalidArgumentException(sprintf(
                'Unknown Colony mark variant "%s". Expected one of: %s.',
                $variant,
                implode(', ', self::VARIANTS),
            ));
        }
        if ($size <= 0) {
            throw new \InvalidArgumentException('Mark size must be a positive integer.');
        }

        $defs = '';
        if ($variant === self::CYAN) {
            $gradId = 'colony-cyan-' . (++self::$seq);
            $stroke = sprintf('url(#%s)', $gradId);
            $dotA = self::CYAN_FROM;
            $dotB = self::CYAN_TO;
            $defs = sprintf(
                '<defs><linearGradient id="%s" x1="20" y1="20" x2="100" y2="100" gradientUnits="userSpaceOnUse">'
                . '<stop stop-color="%s"/><stop offset="1" stop-color="%s"/></linearGradient></defs>',
                $gradId,
                self::CYAN_FROM,
                self::CYAN_TO,
            );
        } else {
            $stroke = $dotA = $dotB = match ($variant) {
                self::WHITE => '#ffffff',
                self::BLACK => '#000000',
                default => 'currentColor',
            };
        }

        $a11y = '';
        $titleEl = '';
        if ($title !== '') {
            $titleId = 'colony-mark-title-' . (++self::$seq);
            $a11y = sprintf(' role="img" aria-labelledby="%s"', $titleId);
            $titleEl = sprintf('<title id="%s">%s</title>', $titleId, htmlspecialchars($title, ENT_QUOTES, 'UTF-8'));
        } else {
            $a11y = ' role="img" aria-hidden="true"';
        }

        return sprintf(
            '<svg xmlns="http://www.w3.org/2000/svg" width="%1$d" height="%1$d" viewBox="0 0 120 120" fill="none"%2$s>'
            . '%3$s%4$s'
            . '<path d="M 85 30 A 40 40 0 1 0 85 90" fill="none" stroke="%5$s" stroke-width="8" stroke-linecap="round"/>'
            . '<circle cx="55" cy="52" r="4.5" fill="%6$s" opacity="0.9"/>'
            . '<circle cx="68" cy="60" r="3.5" fill="%7$s" opacity="0.7"/>'
            . '<circle cx="52" cy="68" r="3" fill="%6$s" opacity="0.6"/>'
            . '</svg>',
            $size,
            $a11y,
            $titleEl,
            $defs,
            $stroke,
            $dotA,
            $dotB,
        );
    }

    /**
     * Absolute filesystem path to a shipped SVG asset.
     *
     * Handy when a framework wants to publish/serve the file itself
     * (e.g. Symfony's asset mapper, Laravel's public disk).
     *
     * @param string $variant one of {@see ColonyBrand::VARIANTS}
     *
     * @throws \InvalidArgumentException for an unknown variant
     */
    public static function assetPath(string $variant = self::CYAN): string
    {
        if (!in_array($variant, self::VARIANTS, true)) {
            throw new \InvalidArgumentException(sprintf('Unknown Colony mark variant "%s".', $variant));
        }
        $file = $variant === self::CURRENT ? 'colony-mark.svg' : sprintf('colony-mark-%s.svg', $variant);

        return dirname(__DIR__) . '/assets/' . $file;
    }

    /**
     * The mark as a `data:` URI, for CSS `background-image`, `<img src>`, or email.
     *
     * @throws \InvalidArgumentException for an unknown variant or a non-positive size
     */
    public static function markDataUri(string $variant = self::CYAN, int $size = 24): string
    {
        return 'data:image/svg+xml;base64,' . base64_encode(self::mark($variant, $size, ''));
    }

    /**
     * An accessible "Log in with the Colony" button (an anchor element).
     *
     * The mark defaults to {@see ColonyBrand::CURRENT}, so it follows the
     * button's text colour for free. Pair with {@see ColonyBrand::buttonStylesheet()}
     * for drop-in styling, or bring your own CSS via the `colony-login-button` class.
     *
     * @param string $href    the authorization URL to start the flow
     * @param array{
     *     label?: string,
     *     theme?: 'auto'|'light'|'dark',
     *     variant?: string,
     *     size?: int,
     *     class?: string,
     *     attributes?: array<string, string|int|bool>
     * } $options
     *
     * @throws \InvalidArgumentException for an empty href, unknown theme, or unknown variant
     */
    public static function loginButton(string $href, array $options = []): string
    {
        if ($href === '') {
            throw new \InvalidArgumentException('loginButton() requires a non-empty href.');
        }

        $label = (string) ($options['label'] ?? self::DEFAULT_LABEL);
        $theme = (string) ($options['theme'] ?? 'auto');
        $variant = (string) ($options['variant'] ?? self::CURRENT);
        $size = (int) ($options['size'] ?? 20);
        $extraClass = trim((string) ($options['class'] ?? ''));

        if (!in_array($theme, self::THEMES, true)) {
            throw new \InvalidArgumentException(sprintf(
                'Unknown button theme "%s". Expected one of: %s.',
                $theme,
                implode(', ', self::THEMES),
            ));
        }

        $classes = 'colony-login-button colony-login-button--' . $theme;
        if ($extraClass !== '') {
            $classes .= ' ' . $extraClass;
        }

        $attrHtml = '';
        /** @var array<string, string|int|bool> $attributes */
        $attributes = $options['attributes'] ?? [];
        foreach ($attributes as $name => $value) {
            // Skip attributes that would let a caller clobber structure/escaping.
            $lower = strtolower((string) $name);
            if (in_array($lower, ['href', 'class'], true) || !preg_match('/^[a-zA-Z][a-zA-Z0-9:_-]*$/', (string) $name)) {
                continue;
            }
            if ($value === false) {
                continue;
            }
            if ($value === true) {
                $attrHtml .= ' ' . $name;
                continue;
            }
            $attrHtml .= sprintf(' %s="%s"', $name, htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8'));
        }

        return sprintf(
            '<a href="%s" class="%s" role="button"%s>'
            . '<span class="colony-login-button__mark" aria-hidden="true">%s</span>'
            . '<span class="colony-login-button__label">%s</span>'
            . '</a>',
            htmlspecialchars($href, ENT_QUOTES, 'UTF-8'),
            htmlspecialchars($classes, ENT_QUOTES, 'UTF-8'),
            $attrHtml,
            self::mark($variant, $size, ''),
            htmlspecialchars($label, ENT_QUOTES, 'UTF-8'),
        );
    }

    /**
     * Default stylesheet for {@see ColonyBrand::loginButton()}.
     *
     * Include once per page (inside a `<style>` tag, or write it to a .css file).
     * Implements the `auto` (follows `prefers-color-scheme`), `light`, and `dark`
     * themes, with a brand-cyan focus ring. Everything is overridable — it only
     * targets the `.colony-login-button` classes.
     */
    public static function buttonStylesheet(): string
    {
        return <<<CSS
            .colony-login-button{display:inline-flex;align-items:center;gap:.5em;
              padding:.55em .9em;border-radius:8px;border:1px solid transparent;
              font:600 14px/1.2 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
              text-decoration:none;cursor:pointer;user-select:none;
              transition:filter .12s ease,box-shadow .12s ease,background-color .12s ease}
            .colony-login-button__mark{display:inline-flex;flex:0 0 auto}
            .colony-login-button:hover{filter:brightness(.97)}
            .colony-login-button:focus-visible{outline:2px solid #00ccff;outline-offset:2px}
            .colony-login-button--light{background:#ffffff;color:#0f1729;border-color:#d8dee9}
            .colony-login-button--dark{background:#0f1729;color:#ffffff;border-color:transparent}
            .colony-login-button--auto{background:#ffffff;color:#0f1729;border-color:#d8dee9}
            @media (prefers-color-scheme:dark){
              .colony-login-button--auto{background:#0f1729;color:#ffffff;border-color:transparent}
            }
            CSS;
    }
}
