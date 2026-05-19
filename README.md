# novexa

Offline-first Android vault app for storing bank account and debit card information with encrypted local storage.

## Features
- Encrypted local storage (no cloud sync)
- Biometric-first unlock with PIN fallback
- Two main tabs: Accounts and Debit Cards (physical + virtual)
- Copy button on all displayed fields
- Custom account fields (shown minimized by default)
- Edit/Delete management from Settings
- Encrypted local backup and restore
- Light/Dark theme toggle

## Build locally
```bash
./gradlew assembleDebug
```

## GitHub Actions
The repository includes `.github/workflows/android-build.yml` to compile the app and upload the debug APK artifact.
