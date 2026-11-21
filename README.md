# GravityBar

GravityBar is a macOS menu bar app for switching Google Antigravity accounts and checking model quotas. It stores saved credentials in macOS Keychain and includes an optional CLI and status bar extension for the standalone Antigravity IDE.

[Download for Mac](https://github.com/Recoba86/GravityBar/releases/latest) · [فارسی](#فارسی)

## Install on Mac

Requires **Apple Silicon** and **macOS 13 or later**.

1. Download `GravityBar-macOS-arm64.dmg` from [Releases](https://github.com/Recoba86/GravityBar/releases/latest).
2. Open the disk image and drag GravityBar into Applications.
3. Open GravityBar, then click its menu bar icon or press `⌥⌘A`. Use **Add New Account** to save an Antigravity session.

The app is ad-hoc signed. macOS may require confirmation on first launch. [Apple’s instructions](https://support.apple.com/en-us/102445)

### Build from source

Building from source requires Xcode Command Line Tools and Python 3.

```sh
git clone https://github.com/Recoba86/GravityBar.git
cd GravityBar
./build_app.sh
```

Run `./install.sh` to install the app and set up the `gravitybar` CLI. The installer registers the IDE extension in existing Antigravity IDE profiles.

## فارسی

گرویتی‌بار یک برنامهٔ نوار منوی مک برای جابه‌جایی میان حساب‌های گوگل آنتی‌گرویتی و مشاهدهٔ سهمیهٔ مدل‌هاست. اطلاعات ورود حساب‌های ذخیره‌شده در کی‌چین مک نگهداری می‌شود.

### نصب روی مک

به مک با تراشهٔ اپل سیلیکون و نسخهٔ ۱۳ یا جدیدتر سیستم‌عامل نیاز دارد.

1. فایل نصب مک را از [صفحهٔ انتشارها](https://github.com/Recoba86/GravityBar/releases/latest) دانلود کنید.
2. فایل را باز کنید و برنامه را به پوشهٔ برنامه‌ها بکشید.
3. گرویتی‌بار را باز کنید. از آیکون نوار منو یا میان‌بر <kbd>⌥⌘A</kbd> استفاده کنید و حساب خود را اضافه کنید.

ممکن است مک در اولین اجرا از شما تأیید بخواهد. [راهنمای اپل](https://support.apple.com/en-us/102445)

برای ساخت از روی کد منبع، دستور ساخت بخش انگلیسی را اجرا کنید.

## License

[MIT License](LICENSE) · Copyright (c) 2026 Recoba86
