# Transcrypt for Sublime Text 4

Encrypt and decrypt a whole document, or one or more selections, with a password.

This is a fork of [eddiejessup/Transcrypt](https://github.com/eddiejessup/Transcrypt), updated for the Python 3.14 plugin host of Sublime Text 4. The original ships compiled PyCrypto modules built for Python 3.3. This fork uses [pyaes](https://github.com/ricmoo/pyaes) instead, a pure Python AES that is included in the package, and adds a stronger encryption format, TC2. It reads everything the original wrote.


## Install

Requires Sublime Text 4, build 4213 or later.

Do not install "Transcrypt" from Package Control. That is the original package, which no longer loads. Clone this repository into your `Packages` folder instead:

Linux:  
```sh
git clone -b dev-ST4 https://github.com/Gregory-K/Transcrypt.git ~/.config/sublime-text/Packages/Transcrypt
```

Windows:  
```pwsh
git clone -b dev-ST4 https://github.com/Gregory-K/Transcrypt.git "$env:APPDATA\Sublime Text\Packages\Transcrypt"

# or CMD
git clone -b dev-ST4 https://github.com/Gregory-K/Transcrypt.git "%APPDATA%\Sublime Text\Packages\Transcrypt"
```

macOS:  
```sh
git clone -b dev-ST4 https://github.com/Gregory-K/Transcrypt.git ~/Library/Application\ Support/Sublime\ Text/Packages/Transcrypt
```

If you used the original package, back up and remove it first. Back up any encrypted notes somewhere safe before you start.


## Usage

The commands are in the context menu under `Transcrypt`, and in the command palette as `Transcrypt: ...`.

- **Encrypt** asks for the password twice.
  - The whole document: select nothing, or select all. If decrypted parts are 'marked', select nothing encrypts only those (see below).
  - Parts of the document: Select the parts to encrypt. Each selection becomes a separate encrypted part.
- **Decrypt** asks for the password once, and auto-recognises the format.
  - Whole encrypted document: Select nothing or select all.
  - TC2 parts within other text: Select the parts to decrypt, or select all. Only the TC2 parts are decrypted, the surrounding text is left as is.
    - If `decrypt_all_parts` is set to true, select nothing to decrypt all TC2 parts at once.
  - Legacy parts within other text: select each one exactly, nothing more.
- **Remember password for this session** asks for the password twice and stores it for the current Sublime Text session. The password remains available until you toggle this option off or quit ST. While it is enabled, Encrypt and Decrypt use the stored password without prompting.

To select several parts at once, hold `ctrl` while you select. This works for both Encrypt and Decrypt.

Errors show in a panel at the status bar.

Text that is already encrypted is never encrypted again.

### Decrypted parts are marked

Each decrypted part gets an outline and a "Transcrypt: decrypted" annotation. The status bar shows the number of decrypted parts in the file.

When nothing is selected, Encrypt re-encrypts all marked parts at once and removes their marks. With no marked parts, it encrypts the entire document.

The marks follow your edits. They exist only in the open file, are never saved, and are lost when you close the file. They serve as reminders only and do not prevent you from saving decrypted text.


## Formats

Choose the format for encryption with the `tc2_format` setting. Decrypt recognises both.

No encryption stays safe for ever. Both formats depend on the strength of your password, and on how well their building blocks hold up against future attacks and faster hardware. TC2 uses current, widely reviewed building blocks and is the stronger of the two. The legacy format has known weaknesses, listed below.

### TC2 format

Recommended. Turn it on with `tc2_format` set `true`. An encrypted part looks like this: `TC2$17.8.1$<salt>$<encrypted text>`

- The key is derived from the password with scrypt and a random salt, so the same password never gives the same key twice, and guessing passwords is slow.
- The text is encrypted as a [Fernet](https://github.com/fernet/spec/blob/master/Spec.md) token, AES-128-CBC with a random IV plus an HMAC-SHA256 checksum. A wrong password or modified text is detected before anything is decrypted.
- A short note takes about 240 characters. Each part takes about a 1/3 second to encrypt or decrypt, during which Sublime Text pauses.
- The token includes the time of encryption, which is not encrypted.

### Legacy format

The format of the original package, and still the default, so existing notes and other installs of the original keep working.

Weaknesses:  
- The password, padded with zero bytes, is used directly as the key. There is no salt and no key derivation.
- It uses AES in ECB mode, so repeated 16-byte blocks of text give repeated blocks of output.
- There is no checksum. A wrong password is only noticed when the result is not valid text, and modified text is not detected.
- Several legacy parts in one document must be selected and decrypted one by one. Encrypted text that was wrapped over several lines cannot be decrypted.

To move a legacy note to TC2, decrypt it, set `"tc2_format": true`, and encrypt it again.


## Settings

Open them from `Preferences > Package Settings > Transcrypt > Settings`,  
or `Preferences: Transcrypt Settings` in the command palette.

```json
{
  // Encrypt with the TC2 format.
  // 'false' writes the legacy format, the original package's one.
  // Decrypt detects the format by itself, whatever the value of this.
  "tc2_format": false,

  // Decrypt with nothing selected, in a document that holds TC2 parts
  // within unencrypted text.
  // 'false' decrypts only selected parts, or a document that is encrypted
  //         in whole (one part).
  // 'true'  decrypts every TC2 part.
  "decrypt_all_parts": false,

  // scrypt memory cost for TC2, in MiB: 128, 64, 32, 16 or 8.
  // All are about equally strong.
  // Lower values suit slower machines with less RAM available.
  "scrypt_memory": 128,
}
```


## Key bindings

No key bindings are active by default.  
`Preferences > Package Settings > Transcrypt > Key Bindings`,  
or `Preferences: Transcrypt Key Bindings` in the command palette, opens the examples next to your own key bindings. Copy the ones you want. On Linux and Windows they are:

```json
[
  {"keys": ["ctrl+k", "e"], "command": "encrypt"},
  {"keys": ["ctrl+k", "d"], "command": "decrypt"},

  // Encrypt, then save. The file is saved only if encryption succeeds.
  {"keys": ["ctrl+k", "ctrl+s"], "command": "encrypt", "args": {"save": true}}
]
```

On macOS, they use `super` instead of `ctrl`. These keys are free in Sublime Text's default key bindings. The [Crypto](https://github.com/mediaupstream/SublimeText-Crypto) package uses the same ones for its own commands.


## Security notes

**Hot exit.** While you edit decrypted text, Sublime Text's hot exit can store it, unencrypted, in its session files when you close the window or quit. Encrypt before closing, or set `"hot_exit": "disabled"` in Preferences.

**Undo.** After encrypting, the plain text is still in the undo history of the open file until you close it.

**Remembered password.** It is kept in memory only, never written to disk, and forgotten when Sublime Text closes or the plugin reloads.

**Lost passwords** cannot be recovered.


## Encrypt on save was removed

The original package had an 'encrypt on save' mode. It only worked through its takeover of `ctrl+s`. Therefore, File > Save, Save All, and the save prompt on closing still wrote the plain text, and pressing `ctrl+s` twice encrypted the text twice.

Rather than offer a protection it could not keep, this fork removes it. Encrypt before saving, or use the encrypt-then-save key binding.


## Finding legacy-encrypted notes

TC2 parts are easy to find with [ripgrep](https://github.com/BurntSushi/ripgrep), since they start with `TC2$`:  
`rg -l 'TC2\$' <notes-dir>`

Legacy output has no marker. This lists the files that **may** contain some:

```sh
rg -P -l '(?<![A-Za-z0-9+/=])(?=\S*\d)(?=\S*[a-z])(?=\S*[A-Z])(?:(?:[A-Za-z0-9+/]{64})*(?:[A-Za-z0-9+/]{22}==|[A-Za-z0-9+/]{43}=)|(?:[A-Za-z0-9+/]{64})+)(?![A-Za-z0-9+/=])' <notes-dir>
```

Use `-n -o` instead of `-l` to see each match with its line number.
Encrypted text that was wrapped over several lines is missed.


## About

Based on  
- [Crypto](https://github.com/mediaupstream/SublimeText-Crypto) by [Derek Anderson](https://github.com/mediaupstream),
- [Transcrypt](https://github.com/eddiejessup/Transcrypt) by Elliot Marsden, which used
  - [Richard Mitchell's fork](https://github.com/mitchellrj/pycrypto) of [PyCrypto](https://github.com/dlitz/pycrypto).  
- AES now comes from [pyaes](https://github.com/ricmoo/pyaes) 1.6.1 by Richard Moore (MIT License), included unchanged in `pyaes/`.


## Authors & Contributors

- [Elliot Marsden](https://github.com/eddiejessup)
- [Derek Anderson](http://twitter.com/derekanderson)
- [Isaac Muse](https://github.com/facelessuser)
- [Richard Mitchell](https://github.com/mitchellrj)
- [Dwayne Litzenberger](https://github.com/dlitz)
- [rexdf](https://github.com/rexdf)
- [Gregory-K](https://github.com/Gregory-K) (Sublime Text 4 fork)


## License

MIT License, see [License.txt](License.txt).  
The included pyaes has its own MIT License, in [pyaes/LICENSE.txt](pyaes/LICENSE.txt).
