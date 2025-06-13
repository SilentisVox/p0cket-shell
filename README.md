<div align="center" markdown="1">
   <a href="https://www.warp.dev/windebloat">
      <img alt="Warp sponsorship" width="736" src="https://github.com/SilentisVox/p0cket-shell/blob/master/assets/p0cket-shell.jpg">
   </a>
</div>

# p0cket-shell

p0cket-shell is an implementation of an exceptionally compact reverse shell, engineered to achieve remote access with the smallest possible memory. This is minimalism without compromising functionality. This is the most size-efficient reverse shell available. This is peak shellcode optimization.

```
╭── тишина ∴ ~\source\gits\p0cket-shell
╰─→ .\p0cket-shell.py
            ____       __        __             __         ____
     ____  / __ \_____/ /_____  / /_      _____/ /_  ___  / / /
    / __ \/ / / / ___/ //_/ _ \/ __/_____/ ___/ __ \/ _ \/ / /
   / /_/ / /_/ / /__/ ,< /  __/ /_/_____(__  ) / / /  __/ / /
  / .___/\____/\___/_/|_|\___/\__/     /____/_/ /_/\___/_/_/
 /_/
 Author: SilentisVox
 Github: https://github.com/SilentisVox/p0cket-shell

usage: p0cket-shell.py [-h] --payload {hardcode,resolve} --LHOST LHOST --LPORT LPORT --format
                       {c,powershell,ps1,python,exe,raw} [--output OUTPUT]
```

### Setup
```powershell
git clone https://github.com/SilenitsVox/p0cket-shell
cd p0cket-shell
python p0cket-shell.py
```

### Usage
```powershell
p0cket-shell.py --payload  [hardcode | resolve]
                --LHOST    [callback ip]
                --LPORT    [callback port]
                --format   [c | powershell | python | exe | raw]
               [--output]  example.py
```