# GeodeCode

Clean code and text before you paste it — strips what you list and proves it, all in your browser.

GeodeCode removes what you tell it to remove — tokens, keys, emails, internal hostnames, anything you name — from any code or text you paste, and shows you exactly what it took out. It also finds what you listed when it is written another way: different capitals or accents, hidden characters, encoded spaces such as %20, a phone number in another format, or tucked inside base64. It flags other things that look sensitive, so you can decide. Everything happens on your device; nothing is uploaded.

## Use it

- **Online** — open [geodeforge.com/geodecode](https://geodeforge.com/geodecode/).
- **Offline** — download `index.html` and open it in any browser. It is one self-contained file: no install, no build, no network.

Paste your text, choose or type what to strip, and copy the cleaned result. The panel lists every change, so you can check it before it goes anywhere.

## Scan a whole folder

On the page, choose **Scan a whole folder** and pick a folder. GeodeCode reads every file in it, in your browser, and lists each file and line that looks like a key, token, password or other secret. Binary files and the `.git` and `node_modules` folders are listed but not read, unless you tick the box to include them.

The same scan runs from the command line, so it can stop a push that would publish a secret. You need Node.js 14 or later. From this folder:

```
node scan-folder.mjs path/to/your-project
```

It prints every file and line it found, with the matched text partly hidden, and exits with 1 if it found anything, 0 if not, 2 if it could not run. Options:

- `--git` reads only the files git would publish (tracked files, and new files that are not ignored). Without it, ignored files such as `.env` are read too, because they go along when a folder is zipped or shared.
- `--include-skipped` also reads `.git` and `node_modules`.
- `--show-values` prints the matched text in full.
- `--receipt receipt.json` writes a receipt with counts only: no file names, no lines, no values. Run it again on the same folder and you get the same bytes.
- `--max-size 50` sets the largest file it reads, in megabytes. Larger files are listed, not skipped silently.

It makes no network calls. The command line and the page run the same code and give the same receipt for the same folder.

## Nothing leaves your device

GeodeCode does all of its work in the page you have open. There is no server, no account, and no third-party request. Open your browser's developer tools, switch to the Network tab, run the tool, and watch — nothing is sent.

That is the difference between a privacy policy and a fact. The whole tool is this one file. Read it.

## License

MIT — see [`LICENSE`](LICENSE). Third-party notices are in [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

## More from GeodeForge

GeodeForge is a one-person studio that crafts open-source tools that do what they say, and let you check — in your browser.

- [GeodeQR](https://geodeforge.com/geodeqr/) — QR codes that never expire
- [GeodePDF](https://geodeforge.com/geodepdf/) — PDF tools that never upload your file

[geodeforge.com](https://geodeforge.com)
