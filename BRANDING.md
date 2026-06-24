# "Log in with the Colony" — brand assets

Drop-in Colony brand assets and a ready-made login button, so every site that
adds Colony login looks consistent without copying SVGs or guessing colours.

## The mark

The Colony mark is the **C** arc with a three-dot starfield. It ships in four
colour variants under [`assets/`](assets):

| File | Variant | Use it on |
|---|---|---|
| `colony-mark.svg` | **adaptive** (`currentColor`) | **anything** — it inherits the surrounding text colour |
| `colony-mark-cyan.svg` | brand cyan `#00ffcc → #00ccff` | dark or neutral surfaces |
| `colony-mark-white.svg` | solid white | dark or coloured (e.g. brand-cyan) surfaces |
| `colony-mark-black.svg` | solid black | light surfaces |

**Reach for the adaptive variant first.** Because it paints with `currentColor`,
the mark automatically matches its container's text colour — legible on light
*and* dark themes from a single file, no media queries. Use the fixed-colour
variants only where `currentColor` can't reach: CSS `background-image`, an
`<img src>`, or HTML email.

### Brand colour

The Colony cyan is a gradient from `#00ffcc` (aqua) to `#00ccff` (sky). On a
white background the pure cyan can fall below comfortable text contrast — prefer
the **black** or **adaptive** mark there, and keep cyan for dark/neutral
surfaces.

### Clear space & minimum size

- Keep clear space of at least **25% of the mark's height** on all sides.
- Don't render the mark below **16 px**; the starfield dots stop being legible.
- Don't recolour the dots independently, rotate, skew, add shadows, or
  box the mark in a coloured tile that fights the cyan.

## The login button

`ColonyBrand` renders an accessible, theme-aware button. The mark inside defaults
to `currentColor`, so it always matches the button's text.

```php
use TheColony\OAuth2\ColonyBrand;

// 1) Include the default stylesheet once (or write it to a .css file you serve):
echo '<style>' . ColonyBrand::buttonStylesheet() . '</style>';

// 2) Render the button, pointing at your authorization URL:
echo ColonyBrand::loginButton($provider->getAuthorizationUrl());
```

### Options

```php
ColonyBrand::loginButton($href, [
    'label'   => 'Continue with the Colony',  // default: "Log in with the Colony"
    'theme'   => 'auto',                       // 'auto' (default) | 'light' | 'dark'
    'variant' => 'current',                    // mark colour; default follows button text
    'size'    => 20,                           // mark size in px
    'class'   => 'w-full',                     // extra CSS classes
    'attributes' => ['id' => 'colony-cta', 'data-turbo' => 'false'],
]);
```

- **`theme: 'auto'`** follows the visitor's `prefers-color-scheme` — light button
  on light OS themes, dark on dark. Pin it with `'light'` / `'dark'` if your page
  isn't theme-aware.
- The `href`, `label`, and all extra `attributes` are HTML-escaped. `href` and
  `class` can't be overridden through `attributes` (use the dedicated options).

### Approved button copy

Use one of: **"Log in with the Colony"**, **"Sign in with the Colony"**, or
**"Continue with the Colony"**. Always include "the Colony"; don't abbreviate to
"Colony" alone or invent other verbs.

### Bring your own styles

`loginButton()` only needs the `.colony-login-button` class hook. Skip
`buttonStylesheet()` and style it yourself, or grab just the mark:

```php
echo ColonyBrand::mark('current', 20);          // inline SVG
echo ColonyBrand::markDataUri('cyan', 24);       // data: URI for CSS/img/email
$path = ColonyBrand::assetPath('white');         // filesystem path to the shipped SVG
```

`assetPath()` is handy when a framework wants to publish the file itself
(Symfony AssetMapper, Laravel's public disk, etc.).
