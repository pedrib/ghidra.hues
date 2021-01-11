### NOTE: this project was originally created by ["quosego"][ref-self]. 
It was shared in a GitHub repository and then deleted by the author. Since the Apache License permits it, I am sharing it here as the original repo does not exist any more.

I did not write this code and do not support it for more than what I need to get it working for me. Having said that, I usually push all changes I make to this repo so it should work out of the box in the latest Ghidra versions.

The original README is below. The releases link is broken, so you will need to build this plugin yourself to get it working in Ghidra.

~ Pedro Ribeiro (pedrib_at_gmail_dot_com)

------------

# ghidra.hues

#### Ghidra: Hues - The Color Plugin

## Brief

This is a simple plugin which provides different colors to the GHIDRA environment.

## Demo

![][ref-demo]

## Building

Run gradlew.bat

Gradle build outputs can be found in Hues//dist//ghidra_A.B_PUBLIC_ZZZZYYXX_Hues.zip

## Installing

1. Download the recent [release][ref-releases]
2. Extract Hues folder from Zip into GHIDRA_INSTALL_DIR//Ghidra//Extensions//
3. Start Ghidra, a prompt of a new plugin has been found should show
4. Activate prompt and start using

## Todos

- [x] Taskbar Icon
- [x] Clean Source Code
- [ ] Avoid theme overwrites
- [x] Profile Management
- [ ] Update Documentation
- [x] Display Preview Sample
- [x] Auto Configuration Saving
- [ ] Selected Window Colorization

## Origin

+ [issue #13][ref-issue]


## Developer

* ["quosego"][ref-self]

## License

This project is licensed under the [Apache License 2.0 (Apache-2.0)][ref-AP2]. See the [LICENSE.md][ref-lic-path] file for details.

[ref-demo]: ./doc/images/MPeg6GJ4Zr.gif
[ref-releases]: https://github.com/quosego/ghidra.hues/releases
[ref-issue]: https://github.com/NationalSecurityAgency/ghidra/issues/13
[ref-self]: https://github.com/quosego
[ref-lic-path]: ./LICENSE.md
[ref-AP2]: https://tldrlegal.com/license/apache-license-2.0-(apache-2.0)
