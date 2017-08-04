pwned-passwords
---------------

See https://haveibeenpwned.com/Passwords for more info.

```
$ wget https://downloads.pwnedpasswords.com/passwords/pwned-passwords-1.0.txt.7z  # +5GB
$ 7z x pwned-passwords-1.0.txt.7z  # +11GB
$ go get github.com/lenartj/pwned-passwords
$ pwned-passwords pwned-passwords-1.0.txt foo foo2 SUPERpw
foo: FOUND
foo2: FOUND
SUPERpw: not found
```

100 searches take about 3 seconds using a slow hdd.
