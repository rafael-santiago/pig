# Build remarks

This document intends to gather useful remarks related with the build. Being taken in consideration
that you have already tried to follow the general build notes, besides the [``Hefesto's``](https://github.com/rafael-santiago/hefesto)
installing notes.

## Clang's support

The version ``0.0.4`` have introduced the automatic usage of ``Clang`` compiler as second option.
Then when ``GCC`` is not installed nor accessible, ``Clang`` is attempted.

This new automation introduces a new dependency which is the ``Hefesto's Clang`` toolset script files.
If you just pulled the ``0.0.4`` changes into your old local copy and is using an old ``Hefesto's``
installation maybe your should being facing errors like these during the build:

```
hefesto WARNING: unable to resolve file name "~/toolsets/clang/clang-app.hsl"
hefesto WARNING: unable to resolve file name "~/toolsets/clang/clang-app.hsl"
```

The warning shown above indicates that your ``Hefesto's`` copy does not have the ``Clang's`` toolset
installed. For installing it you need to clone [``Helios``](https://github.com/rafael-santiago/helios)
and asks it for copying the ``Clang's`` toolset into your ``Hefesto's`` include base. As follows:

```
you@SOMEWHERE:~/over/the/rainbow# git clone https://github.com/rafael-santiago/helios
you@SOMEWHERE:~/over/the/rainbow# cd helios
you@SOMEWHERE:~/over/the/rainbow/helios# hefesto --install=clang-c-toolset
```

Now you can back to your ``pig's`` local copy and try to build it.

It should be working fine.

## How to force the usage of one specific compiler

Until now the ``pig's`` build have written to support the usage of two compilers: ``GCC`` or ``Clang``.

The default is ``GCC``. When it is not present the ``Clang`` is attempted.

However, you can force the usage of one by the option ``--toolset=<toolset-name>``. For ``GCC`` usage
you should call:

```
you@SOMEWHERE:~/over/the/rainbow/pig/src# hefesto --toolset=gcc-c-app
```

For ``Clang``:

```
you@SOMEWHERE:~/over/the/rainbow/pig/src# hefesto --toolset=clang-c-app
```
