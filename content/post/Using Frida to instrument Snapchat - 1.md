---
author: "Axi0mS"
date: 2017-03-16
linktitle: Using Frida to instrument Snapchat - 1
title: Using Frida to instrument Snapchat - 1
weight: 10
---

Few years ago I took some days to take a look at Snapchat Android application when it came out on the market. Nobody was supposed to be able to keep the pictures you were sending, and if they did screenshot them, you would be notified. Of course, some people decided to dig into Snapchat internals and so did I. I was able to recover the original pictures using the symetric key they were using. (If you did the same at that time, **_M02cnQ51Ji97vwT4_** must be familiar to you)
Few weeks ago I started using Snapchat again, and decided to take another look at it. But this time I thought it would be interesting to have a different approach and to recover pictures differently. Dynamic Binary Instrumentation (and especially Frida) looked pretty interesing for this task so I gave it a try.

# Dynamic Binary Instrumentation : Frida

## Dyna... What ?

I won't go into too much details, because this is not the subject of this article. I found a great description of what **Dynamic Binary Instrumentation** is, so i will just quote it :
>_" Dynamic Binary Instrumentation (DBI) is a method of analyzing the behavior of a binary application at runtime through the injection of instrumentation code. This instrumentation code executes as part of the normal instruction stream after being injected. In most cases, the instrumentation code will be entirely transparent to the application that it's been injected to. "_

To be able to instrument a binary (in our case Snapchat), we need an instrumentation framework. I chose Frida.

## What about Frida ?

**Frida** is designed to instrument different kind of binaries and is working pretty well with Android. It let us analyze the application, set hooks on functions, set callbacks, dump memory, modify memory at runtime...

>_"It's a dynamic code instrumentation toolkit. It lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, Linux, iOS, Android, and QNX."_

There are already different tools that can secretly dump Snaps. Some **_Xposed_** modules like **_SnapPrefs_** work really well, and is fully automated to do so. The aim of this article is not to developp a fully working tool that would allow anybody to save Snaps but only an experiment to see how one could be able to intercept data using Frida.


# First steps with Frida

You can find a quick-start guide browsing the [Frida](https://www.frida.re/docs/quickstart/) website, so I won't go into too much details about the setup. Download the latest [frida-server](https://github.com/frida/frida/releases) for your device and push it onto it.

```console
$ adb push frida-server /data/local/tmp/
5792 KB/s (46726696 bytes in 7.877s)
```

We now have to start the Frida server on our device so we can interact with it remotely.

```console
$ adb shell
$ shell@hero2lte:/ su
$ root@hero2lte:/ chmod 755 /data/local/tmp/frida-server
$ root@hero2lte:/ /data/local/tmp/frida-server &
[1] 4022
```

Now that we started the server, we can finally start playing with Frida !
Using the frida binary with the **-U** flag we can remotely access our device and put the name of the application we want to instrument (here **com.snapchat.android**).

```console
$ frida -U com.snapchat.android
     ____
    / _  |   Frida 9.1.12 - A world-class dynamic instrumentation framework
   | \(_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

[USB::Samsung SM-G935F::com.snapchat.android]->

```
There you can play with the _REPL_ (Read Eval Print Loop), most of its features are documented on the official website.

# Enumerating modules
I kinda started out of nothing, so I thought it would be a good idea to start by listing loaded libraries :

```ruby
[USB::Samsung SM-G935F::com.snapchat.android]-> Process.enumerateModulesSync()
[...]
{
    "base": "0xf6d7a000",
    "name": "libc.so",
    "path": "/system/lib/libc.so",
    "size": 499712
},
{
    "base": "0xf6dfe000",
    "name": "libc++.so",
    "path": "/system/lib/libc++.so",
    "size": 581632
},
[...]

[USB::Samsung SM-G935F::com.snapchat.android]-> Process.enumerateModulesSync().length
178
```
As you can see on the previous session, there are plenty of modules being loaded in the Snapchat application. Since we are interested in pictures, there are 2 libraries that are of interest to us : **libpng** and **libjpeg**. Both deal with pictures so they must be involved in snaps management. But why are they both loaded ?

# Analyzing **libpng.so**
I chose to have a look at **libpng** first. My aim was to find something that could look like the PNG magic number : "**â€°PNG**" (or **[0x89, 0x50, 0x4E, 0x47]**). I decided to enumerate all functions from libpng.

```ruby
[USB::Samsung SM-G935F::com.snapchat.android]-> Module.enumerateExportsSync("libpng.so")[...]
[...]
{
    "address": "0xf59ace95",
    "name": "png_get_palette_max",
    "type": "function"
},
{
    "address": "0xf59b1ba9",
    "name": "png_read_data",
    "type": "function"
},
{
    "address": "0xf59ba355",
    "name": "png_set_unknown_chunks",
    "type": "function"
},
[...]

[USB::Samsung SM-G935F::com.snapchat.android]-> Module.enumerateExportsSync("libpng.so").length
397
```

There are hundreds of function we could look at (397 actually). I just scrolled those function and one looked promising (other functions might have worked too) : **png_read_data**. Since libpng is pretty well documented I just loaded its documentation [png_read_data documentation](http://docs.ros.org/api/openhrp3/html/pngrio_8c.html#aea8e29d925514e5649502d349cb706bb) :

```C
void png_read_data 	(
   	png_structp  	png_ptr,
		png_bytep  	data,
		png_size_t  	length
) 	
```
Awesome ! Looks like the second argument is a pointer to the PNG data ! Using Frida, we can set a callback when **png_read_data** is being called, thus we can inspect memory and maybe find the snap we are looking for !

```js
Address = Module.findExportByName("libpng.so", "png_read_data");
var DataPNG = 0
Interceptor.attach(ptr(Address), {
    onEnter: function(args){
        DataPNG = ptr(args[1]);
    },
    onLeave: function(retval){
      console.log(Memory.readByteArray(DataPNG, 200))
    },

});
```
A bit of explanation here. I first load the address of **png_read_data** and set a callback when the function is being called. When the function is being called (**onEnter**), we store the second argument : **args[1]** (**png_bytep data**) into **DataPNG**.
When **png_read_data** is going to exit (**onLeave**), we use Frida to read some bytes at the location pointed by **DataPNG** (we are reading only the first 200 bytes).
(_**png_read_data** is being called multiple times, it reads chunk of PNG each time it is being called so we have a lot to process_)

So now, we just take a snap and see what is happening :

```
0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  89 50 4e 47 0d 0a 1a 0a 00 00 00 00 00 00 00 00  .PNG............
00000010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000c0  00 00 00 00 00 00 00 00                          ........
[...]
0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  00 00 00 0d 49 48 44 52 cb 5e 0f 33 00 d4 ef b0  ....IHDR.^.3....
00000010  00 00 82 a9 90 92 f8 ff e1 ee a0 f6 52 44 48 49  ............RDHI
00000020  99 e2 9a f5 b0 7b 2e ad 00 00 00 00 00 00 00 00  .....{..........
00000030  90 92 f8 ff e1 ee a0 f6 b0 7b 2e ad b0 7b 2e ad  .........{...{..
00000040  18 93 f8 ff 00 00 00 00 59 e6 a0 f6 00 00 00 00  ........Y.......
00000050  00 00 00 00 40 00 00 00 00 00 00 00 c0 d0 a7 34  ....@..........4
00000060  40 00 00 00 f0 3e 40 ad b0 7b 2e ad 00 d4 ef b0  @....>@..{......
00000070  00 00 82 a9 2d 00 10 00 00 00 00 00 00 45 8a f4  ....-........E..
00000080  a4 90 f8 ff ec 90 f8 ff 4c 91 f8 ff f0 3e 40 ad  ........L....>@.
00000090  f5 ee a0 f6 44 91 f8 ff 00 00 00 80 2c 98 f8 ff  ....D.......,...
000000a0  cb 78 99 f6 00 00 57 00 78 de 7f f4 44 91 f8 ff  .x....W.x...D...
000000b0  4c 91 f8 ff f0 3e 40 ad 88 27 7b f4 01 00 00 00  L....>@..'{.....
000000c0  54 1c 7b f4 00 00 00 00                          T.{.....
[...]
```

We can see the PNG magic number, along with other part of the header ! Let's write something a bit fancier to dump PNG from memory !
For this we will use python bindings, the JS engine running on the phone will dump the memory each time **png_read_data** is being called and send it to the python handler running on the host machine. Since **png_read_data** seems to be called multiple times before the PNG is fully read, we will detect the EOF of a PNG file (**[0xAE, 0x42, 0x60, 0x82]**). As soon as this is detected, we write the buffer on the disk and wait for the next PNG to be read. Everything has been automatized in this script :

```python
from __future__ import print_function
import frida
import sys

Lib = "libpng.so"
Func = "png_read_data"
PATH = "/path/to/output/png"


def on_message(message, data):
    print(message["payload"])

    on_message.PNG = on_message.PNG + message["payload"]
    if (message["payload"] == [0xAE, 0x42, 0x60, 0x82]): # PNG EOF
        f = open(PATH + "OUT" + str(on_message.element) + ".PNG", "wb")
        f.write(bytearray(on_message.PNG))
        f.close()
        on_message.PNG = []
        on_message.element += 1

if __name__ == '__main__':
    session = frida.get_usb_device().attach('com.snapchat.android')
    print("Attached.")
    script = session.create_script("""
        var Address = Module.findExportByName("libpng.so", "png_read_data");
        DataPNG = null
        LengthPNG = null
        Interceptor.attach(ptr(Address), {
          onEnter: function(args){
            DataPNG = ptr(args[1]);
            LengthPNG = parseInt(args[2]);
          },
          onLeave: function(args, retval){

            var Dump = Memory.readByteArray(DataPNG, LengthPNG)
            var Payload = []
			for (i=0; i<Dump.length; i++){
				Payload.push(Dump[i]);
			}
            send(Payload)
          },
        });

    """)

    script.on('message', on_message)
    script.load()
    on_message.PNG = []
    on_message.element = 0
    sys.stdin.read()
```

And here we go ! We can now get our snaps from memor... What ?



![OUT 0](/post/images/OUT0.PNG)
![OUT 1](/post/images/OUT1.PNG)
![OUT 2](/post/images/OUT2.PNG)


Those are not snaps ?
All the dumped PNG I collected are just ressources from snapchat, like logo, buttons and stuff.. 


##### References
* [uninformed.org - DBI](http://uninformed.org/index.cgi?v=7&a=1&p=3)
* [Frida](https://www.frida.re/)
* [Snapprefs](https://forum.xda-developers.com/xposed/modules/app-snapprefs-ultimate-snapchat-utility-t2947254)
