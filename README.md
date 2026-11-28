# GravityBar

GravityBar is a macOS menu bar app for switching Google Antigravity accounts and checking model quotas. It stores saved credentials in macOS Keychain and includes an optional CLI and status bar extension for the standalone Antigravity IDE.

[Download for Mac](https://github.com/Recoba86/GravityBar/releases/latest) · [فارسی](#فارسی)

## Install on Mac

Requires **Apple Silicon** and **macOS 13 or later**.

1. Download `GravityBar-macOS-arm64.dmg` from [Releases](https://github.com/Recoba86/GravityBar/releases/latest).
2. Open the disk image and drag GravityBar into Applications.
3. Open GravityBar, then click its menu bar icon or press `⌥⌘A`. Use **Add New Account** to save an Antigravity session.

The app is ad-hoc signed. macOS may require confirmation on first launch. [Apple’s instructions](https://support.apple.com/en-us/102445)

## Checking quotas

Press **Check** in the menu to see every saved account's quota. GravityBar runs the official Antigravity CLI (`agy -p /quota`) for each account with a 6-second pause between checks. The menu shows the last successful result and reports any failed check. Checks run only on request.

Quota checks need the Antigravity CLI, usually installed at `~/.gemini/bin/agy`. GravityBar passes the saved credential to the CLI in a temporary profile. The CLI handles authentication and the quota request.

GravityBar is an independent app. Google documents `/quota` in the official CLI. Its documentation does not confirm support for GravityBar's use of temporary profiles with saved credentials. Google's terms restrict third-party access and bypassing usage limits. [Antigravity quota documentation](https://antigravity.google/docs/cli/commands/usage/) · [Antigravity terms](https://antigravity.google/terms) · [Google terms](https://policies.google.com/terms)

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

### بررسی سهمیه

برای دیدن سهمیهٔ همهٔ حساب‌ها، دکمهٔ بررسی را در منو بزنید. گرویتی‌بار ابزار خط فرمان رسمی آنتی‌گرویتی را برای هر حساب یک بار و با چند ثانیه فاصله اجرا می‌کند. در پس‌زمینه هیچ بررسی‌ای انجام نمی‌شود.

گرویتی‌بار به سرورهای داخلی گوگل وصل نمی‌شود و خودش را جای برنامهٔ دیگری معرفی نمی‌کند.

گرویتی‌بار یک برنامهٔ مستقل است. گوگل دستور سهمیه را در ابزار رسمی مستند کرده است، اما استفادهٔ گرویتی‌بار از پروفایل موقت با اطلاعات ورود ذخیره‌شده در این مستندات تأیید نشده است. شرایط گوگل دسترسی با ابزارهای شخص ثالث و دور زدن محدودیت‌های استفاده را محدود می‌کند. [شرایط آنتی‌گرویتی](https://antigravity.google/terms) · [شرایط گوگل](https://policies.google.com/terms)

برای ساخت از روی کد منبع، دستور ساخت بخش انگلیسی را اجرا کنید.

## License

[MIT License](LICENSE) · Copyright (c) 2026 Recoba86
