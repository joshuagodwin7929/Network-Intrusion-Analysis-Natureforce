# Lab setup

I did all of this inside a Kali Linux virtual machine. A pcap is a recording, so nothing live gets touched. The only risk is a file extracted from it, and I only hashed those and never opened or ran them.

## Tools

```bash
sudo apt update
sudo apt install -y wireshark tshark unzip git mono-complete
sudo usermod -aG wireshark $USER      # log out and back in afterwards
```

Versions: Wireshark 4.6.6, TShark 4.6.6, Capinfos 4.6.6 (see `screenshots/00-lab-wireshark-version.png`).

## Project folder

```bash
mkdir -p ~/network-intrusion-analysis-natureforce/{pcaps,evidence,screenshots,report}
cd ~/network-intrusion-analysis-natureforce
git init && git branch -m main
printf "pcaps/\n*.exe\n*.dll\nevidence/extracted/\n" > .gitignore
```

## NetworkMiner 3.2 under Mono

NetworkMiner isn't in Kali's repositories, so `apt install networkminer` fails with "Unable to locate package". The Windows build runs under Mono instead:

```bash
cd /tmp
wget "https://www.netresec.com/?download=NetworkMiner" -O networkminer.zip
sudo unzip networkminer.zip -d /opt/
sudo chmod +x /opt/NetworkMiner_3-2/NetworkMiner.exe
```

The folder name uses a hyphen (`NetworkMiner_3-2`). On my Kali install it crashed at startup with `File must be smaller than 4K`, which is Mono choking on an oversized terminfo file. Setting `TERM=xterm` didn't fix it. This launch command did:

```bash
cd /opt/NetworkMiner_3-2
TERM=dumb XMODIFIERS= mono NetworkMiner.exe --noupdatecheck
```

I made it an alias:

```bash
echo "alias networkminer='cd /opt/NetworkMiner_3-2 && TERM=dumb XMODIFIERS= mono NetworkMiner.exe --noupdatecheck'" >> ~/.zshrc
source ~/.zshrc
```

A `Gtk not found ... using built-in colorscheme` message is harmless. You can see it running in `screenshots/00-lab-networkminer-running.png`.

I installed NetworkMiner, but every finding in this project came from Wireshark and tshark.

## Handling the sample

- Work offline or on NAT, in a VM with a snapshot taken before you open the pcap.
- Save extracted objects in `evidence/extracted/`, which git ignores.
- Hash it, run `file` on it, and look it up by hash. Don't double-click, open or execute it.
- Search VirusTotal by hash or IP. Don't upload the sample.
