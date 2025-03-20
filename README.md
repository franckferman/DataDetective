<div id="top" align="center">

<!-- Shields Header -->
[![Contributors][contributors-shield]](https://github.com/franckferman/DataDetective/graphs/contributors)
[![Stargazers][stars-shield]](https://github.com/franckferman/DataDetective/stargazers)
[![License][license-shield]](https://github.com/franckferman/DataDetective/blob/stable/LICENSE)

<!-- Logo -->
<a href="https://github.com/franckferman/DataDetective">
  <img src="https://raw.githubusercontent.com/franckferman/DataDetective/refs/heads/stable/docs/github/graphical_resources/Logo-without_background-DataDetective.png" alt="DataDetective Logo" width="auto" height="auto">
</a>

<!-- Title & Tagline -->
<h3 align="center">🕵️‍♂️ DataDetective</h3>
<p align="center">
    <em> Unlock the story hidden in data.</em>
    <br>
     Your digital investigation partner.
</p>

</div>

## 📜 Table of Contents

<details open>
  <summary><strong>Click to collapse/expand</strong></summary>
  <ol>
    <li><a href="#-about">📖 About</a></li>
    <li><a href="#-installation">🛠️ Installation</a></li>
    <li><a href="#-usage">🎮 Usage</a></li>
    <li><a href="#-license">📜 License</a></li>
    <li><a href="#-contact">📞 Contact</a></li>
  </ol>
</details>

## 📖 About

**⚠️ DataDetective is a work in progress**

Although already useful in **specific forensic investigation scenarios**, the project is still **far from complete**. The current version serves as a foundation for what will eventually become a much more **powerful**, **versatile**, and **feature-rich** forensic analysis tool.

### **What is DataDetective**

DataDetective is a Python-based tool designed to **extract, analyze, and interpret forensic evidence** from **EWF disk images** and raw storage dumps. It aims to provide investigators with a **reliable** and **efficient** method to uncover critical data for forensic analysis.

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🚀 Installation

### Prerequisites  

- **Linux** (Tested on **Debian GNU/Linux 12 Bookworm**, but should work on other distributions).  
- **Python 3** (latest stable version recommended).  
- **The Sleuth Kit (TSK)** - Essential for forensic disk analysis.  
- **RegRipper** - Critical for extracting Windows registry artifacts.  

### Getting DataDetective

#### Option 1: One-liner with `Invoke-WebRequest` (Recommended)
```shell
curl -O https://github.com/franckferman/DataDetective/blob/stable/src/DataDetective/DataDetective.py
```

#### Option 2: Clone via Git
```shell
git clone https://github.com/franckferman/DataDetective.git
```

#### Option 3: **Direct Download** from GitHub
1. Go to GitHub repo.
2. Click `<> Code` → `Download ZIP`.
3. Extract the archive to your desired location.

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🎮 Usage

### Getting started

Once installed, you can start using DataDetective with the following commands:

❔ Get Help:
```shell
python3 DataDetective.py -h
```

⚖️ Check Image Integrity:
```shell
python3 DataDetective.py -i image.ewf --check-image
```

📋 List Image Partitions:
```shell
python3 DataDetective.py -i image.ewf --show-partitions
```

📁 List Partition Files:
```shell
python3 DataDetective.py -i image.ewf --show-files
python3 DataDetective.py -i image.ewf --show-files -r  # Recursive listing
```

🗂️ Show a Specific Directory:
```shell
python3 DataDetective.py -i image.ewf --show-dir /path/to/directory
```

🔎 Extract Data:
```shell
python3 DataDetective.py -i image.ewf -e ALL -o /path/for/output
```

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 📚 License

This project is licensed under the GNU Affero General Public License, Version 3.0. For more details, please refer to the LICENSE file in the repository: [Read the license on GitHub](https://github.com/franckferman/DataDetective/blob/stable/LICENSE)

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 📞 Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/franckferman/DataDetective.svg?style=for-the-badge
[contributors-url]: https://github.com/franckferman/DataDetective/graphs/contributors
[stars-shield]: https://img.shields.io/github/stars/franckferman/DataDetective.svg?style=for-the-badge
[stars-url]: https://github.com/franckferman/DataDetective/stargazers
[license-shield]: https://img.shields.io/github/license/franckferman/DataDetective.svg?style=for-the-badge
[license-url]: https://github.com/franckferman/DataDetective/blob/stable/LICENSE
[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=blueviolet
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=blue
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=blue
