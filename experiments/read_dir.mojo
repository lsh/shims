"""
A port of the code from this stack overflow answer:
https://stackoverflow.com/a/4204758

```c
#include <dirent.h> 
#include <stdio.h> 

int main(void) {
  DIR *d;
  struct dirent *dir;
  d = opendir(".");
  if (d) {
    while ((dir = readdir(d)) != NULL) {
      printf("%s\n", dir->d_name);
    }
    closedir(d);
  }
  return(0);
}
```
"""
from memory.unsafe import Pointer
from sys.info import sizeof


@value
@register_passable("trivial")
struct DIR:
    pass


@value
@register_passable("trivial")
struct dirent:
    var d_ino: UInt64
    var d_off: UInt64
    var d_reclen: UInt16
    var d_type: UInt8
    var d_name: Pointer[UInt8]


@always_inline
fn closedir(arg: Pointer[DIR]) -> Int32:
    return external_call["closedir", Int32, Pointer[DIR]](arg)


@always_inline
fn opendir(arg: Pointer[UInt8]) -> Pointer[DIR]:
    return external_call["opendir", Pointer[DIR], Pointer[UInt8]](arg)


@always_inline
fn readdir(arg: Pointer[DIR]) -> Pointer[dirent]:
    return external_call["readdir", Pointer[dirent], Pointer[DIR]](arg)


@always_inline
fn fdopendir(arg: Int32) -> DIR:
    return external_call["fdopendir", DIR](arg)


# based on "https://github.com/crisadamo/mojo-libc/blob/main/Libc.mojo"
@always_inline
fn str_to_cstring(s: String) -> Pointer[UInt8]:
    let ptr = Pointer[UInt8].alloc(len(s) + 1)
    for i in range(len(s)):
        ptr.store(i, ord(s[i]))
    ptr.store(len(s), ord("\0"))
    return ptr


fn main():
    var dir = Pointer[dirent]()
    let path = str_to_cstring(".")
    let d = opendir(path)
    if d:
        while dir := readdir(d):
            let direntry = dir.load(0)
            # let dname = StringRef(
            #     direntry.d_name.bitcast[__mlir_type.`!pop.scalar<si8>`]().address,
            #     direntry.d_reclen.to_int(),
            # )
            let ptr = dir.bitcast[__mlir_type.`!pop.scalar<si8>`]().offset(
                sizeof[UInt64]() * 2 + sizeof[UInt16]() + sizeof[UInt8]()
            ).address
            let dname = StringRef(
                ptr,
                dir.load(0).d_reclen.to_int(),
            )
            print(dname)
        let _closed_ok = closedir(d)
    path.free()
