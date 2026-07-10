Title: Live Content

Description: Fetched live

Source: https://raw.githubusercontent.com/soxoj/maigret/main/README.md

---

# Maigret

<div align="center">
  <div>
    <a href="https://pypi.org/project/maigret/">
        <img alt="PyPI version badge for Maigret" src="https://img.shields.io/pypi/v/maigret?style=flat-square" />
    </a>
    <a href="https://pepy.tech/project/maigret">
      <img alt="Total downloads" src="https://static.pepy.tech/badge/maigret" />
      <img alt="Downloads/month" src="https://static.pepy.tech/badge/maigret/month" />
    </a>
  </div>
  <div>
    <a href="https://github.com/soxoj/maigret">
        <img alt="View count for Maigret project" src="https://komarev.com/ghpvc/?username=maigret&color=brightgreen&label=views&style=flat-square" />
    </a>
    <a href="https://github.com/soxoj/maigret">
        <img alt="Minimum Python version required: 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-brightgreen?style=flat-square" />
    </a>
    <a href="https://github.com/soxoj/maigret/blob/main/LICENSE">
        <img alt="License badge for Maigret" src="https://img.shields.io/github/license/soxoj/maigret?style=flat-square" />
    </a>
  </div>
  <br>
  <div>
    <img src="https://raw.githubusercontent.com/soxoj/maigret/main/static/maigret.png" height="300" alt="Maigret logo"/>
  </div>
  <br>
  <div>
    <a href="https://codewiki.google/github.com/soxoj/maigret">
        <img alt="Ask Code Wiki about Maigret" src="https://img.shields.io/badge/Code_Wiki-ask_about_repo-yellow?logo=googlegemini" />
    </a>
    <a href="https://deepwiki.com/soxoj/maigret">
        <img alt="Ask DeepWiki about Maigret" src="https://img.shields.io/badge/DeepWiki-ask_about_repo-yellow" />
    </a>
  </div>
  <br>
  <div>
    <b>English</b> · <a href="README.zh-CN.md">简体中文</a>
  </div>
  <br>
</div>

**Maigret** collects a dossier on a person **by username only**, checking for accounts on a huge number of sites and gathering all the available information from web pages. No API keys required. **[AI profiling (demo)](#ai-analysis)**. 

## Sponsors

<p align="center">
  <a href="https://www.711proxy.com/?utm_t=1&utm_i=538">
    <img src="https://i.imgur.com/MxLEDsQ.gif" width="250" alt="711Proxy">
  </a>
</p>

<p>
  <a href="https://www.711proxy.com/?utm_t=1&utm_i=538"><b>711Proxy</b></a> provides reliable residential proxies for web scraping, username lookups, and public data collection. Over <b>100M</b> residential IPs across <b>200+</b> countries** • High Success Rates • Fast & Reliable Connections. <br>
<b>Special Offer</b>: Free trial available! Rotating residential proxies from just <b>$0.55/GB</b>. Unlimited residential proxies from <b>$15/hour</b> with no concurrency limits.
</p>

<br>

<p align="center">
  <a href="https://9proxy.com/?utm_source=Github&utm_campaign=obscura">
    <img src="https://i.imgur.com/FleHdvu.gif" width="250" alt="9Proxy">
  </a>
</p>

<p>
  <a href="https://9proxy.com/?utm_source=Github&utm_campaign=obscura"><b>9Proxy</b></a> provides residential proxies from just <b>$0.018/IP or $0.68/GB</b>. 20M+ IPs across 90+ countries. Sticky or rotating sessions, managed from desktop or mobile app.
</p>

## Contents

- [In one minute](#in-one-minute)
- [Main features](#main-features)
- [Demo](#demo)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [Commercial Use](#commercial-use)
- [About](#about)

<a id="one-minute"></a>
## In one minute

Ensure you have Python 3.10 or higher.

```bash
pip install maigret
maigret YOUR_USERNAME
```

No install? Try the [community Telegram bot](https://sites.google.com/view/maigret-bot-link) or a [Cloud Shell](#cloud-shells). 

Want a web UI? See [how to launch it](#web-interface).

See also: [Quick start](https://maigret.readthedocs.io/en/latest/quick-start.html). 

## Main features

- Supports 3,000+ sites ([see full list](https://github.com/soxoj/maigret/blob/main/sites.md)). A default run checks the 500 highest-ranked sites by traffic; pass `-a` to scan everything, or `--tags` to narrow by category/country.
- Embeddable in Python projects — import `maigret` and run searches programmatically (see [library usage](https://maigret.readthedocs.io/en/latest/library-usage.html)).
- [Extracts](https://github.com/soxoj/socid_extractor) all available information about the account owner from profile pages and site APIs, including links to other accounts.
- Performs recursive search using discovered usernames and other IDs.
- Allows filtering by tags (site categories, countries).
- Detects and partially bypasses blocks, censorship, and CAPTCHA.
- Fetches an [auto-updated site database](https://maigret.readthedocs.io/en/latest/settings.html#database-auto-update) from GitHub each run (once per 24 hours), and falls back to the built-in database if offline.
- Works with Tor and I2P websites; able to check domains.
- Ships with a [web interface](#web-interface) for browsing results as a graph and downloading reports in every format from a single page.
- Optional [AI analysis mode](#ai-analysis) (`--ai`) that turns raw findings into a short investigation summary using an OpenAI-compatible API.

For the complete feature list, see the [features documentation](https://maigret.readthedocs.io/en/latest/features.html).

### Used by

Professional OSINT and social-media analysis tools built on Maigret:

<a href="https://github.com/SocialLinks-IO/sociallinks-api"><img height="60" alt="Social Links API" src="https://github.com/user-attachments/assets/789747b2-d7a0-4d4e-8868-ffc4427df660"></a>
<a href="https://sociallinks.io/products/sl-crimewall"><img height="60" alt="Social Links Crimewall" src="https://github.com/user-attachments/assets/0b18f06c-2f38-477b-b946-1be1a632a9d1"></a>
<a href="https://usersearch.ai/"><img height="60" alt="UserSearch" src="https://github.com/user-attachments/assets/66daa213-cf7d-40cf-9267-42f97cf77580"></a>

## Demo

### Video

<a href="https://asciinema.org/a/Ao0y7N0TTxpS0pisoprQJdylZ">
  <img src="https://asciinema.org/a/Ao0y7N0TTxpS0pisoprQJdylZ.svg" alt="asciicast" width="600">
</a>

### Reports

[PDF report](https://raw.githubusercontent.com/soxoj/maigret/main/static/report_alexaimephotographycars.pdf), [HTML report](https://htmlpreview.github.io/?https://raw.githubusercontent.com/soxoj/maigret/main/static/report_alexaimephotographycars.html)

![HTML report screenshot](https://raw.githubusercontent.com/soxoj/maigret/main/static/report_alexaimephotography_html_screenshot.png)

![XMind 8 report screenshot](https://raw.githubusercontent.com/soxoj/maigret/main/static/report_alexaimephotography_xmind_screenshot.png)

[Full console output](https://raw.githubusercontent.com/soxoj/ma

