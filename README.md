# C2 Tracker

This repo is a modified fork of [Montysecurity C2-Tracker](https://github.com/montysecurity/C2-Tracker)

C2-Tracker mines various C2/malware IPs from Shodan. Most of the searches used were sourced from [Michael Koczwara's](https://michaelkoczwara.medium.com/) and [@BushidoToken's (Will's)](https://twitter.com/BushidoToken) research (see references below). Huge thanks to the both of them!

## What is tracked?

- C2's
    - [Cobalt Strike](https://www.cobaltstrike.com/)
    - [Metasploit Framework](https://www.metasploit.com/)
    - [Covenant](https://github.com/cobbr/Covenant)
    - [Mythic](https://github.com/its-a-feature/Mythic)
    - [Brute Ratel C4](https://bruteratel.com/)
    - [Posh](https://github.com/nettitude/PoshC2)
    - [Sliver](https://github.com/BishopFox/sliver)
    - [Deimos](https://github.com/DeimosC2/DeimosC2)
    - PANDA
    - [NimPlant C2](https://github.com/chvancooten/NimPlant)
    - [Havoc C2](https://github.com/HavocFramework/Havoc)
- Malware
    - AcidRain Stealer
    - Misha Stealer (AKA Grand Misha)
    - Patriot Stealer
    - RAXNET Bitcoin Stealer
    - Titan Stealer
    - Collector Stealer
    - Mystic Stealer
- Tools
    - [Hashcat Cracking Tool](https://hashcat.net/hashcat/)
    - [BurpSuite](https://portswigger.net/burp)
    - [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
    - [XMRig Monero Cryptominer](https://xmrig.com/)
    - [GoPhish](https://getgophish.com/)

## Current State

This script uses GithubAction nightly to automatically update the files in `data`.

### Running Locally

However if you want to host a private version, put your Shodan API key in an environment variable called `SHODAN_API_KEY`

```bash
echo SHODAN_API_KEY=API_KEY >> .env
source .env
python3 -m pip install -r requirements.txt
python3 tracker.py
```

## References

- [Hunting C2 with Shodan by Michael Koczwara](https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f)
- [Hunting Cobalt Strike C2 with Shodan by Michael Koczwara](https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2)
- [This tweet](https://twitter.com/MichalKoczwara/status/1591750513238118401?cxt=HHwWgsDUiZGqhJcsAAAA)
- BushidoToken's [OSINT-SearchOperators](https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md)
- [This tweet](https://twitter.com/MichalKoczwara/status/1641119242618650653)
- [This tweet](https://twitter.com/MichalKoczwara/status/1641676761283850241)
- [This tweet](https://twitter.com/_montysecurity/status/1643164749599834112)