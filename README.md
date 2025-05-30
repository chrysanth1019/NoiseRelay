# NoiseRelay

NoiseRelay is a C-based project that uses the GNU autotools build system. It includes submodules and requires several system dependencies like `libtool`, `bison`, and `flex`.

---

## Prerequisites

Make sure you have the following tools installed:

- `git`
- `build-essential` (for compilers and make)
- `autotools` components: `autoconf`, `automake`, `libtool`
- `bison`, `flex`
- `pkg-config` (optional, if dependencies use it)

On Debian/Ubuntu-based systems:

```bash
sudo apt update
sudo apt install git build-essential libtool bison flex autoconf automake pkg-config -y
```

---
## Clone repository
```bash
sudo git clone --recurse-submodules https://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@github.com/chrysanth1019/NoiseRelay.git
cd NoiseRelay
sudo chmod 777 build.sh
./build.sh
```

